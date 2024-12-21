import csv
import io
import json
import gzip
import operator
import os.path
import pathlib
import re
import sys
import subprocess

import bs4
import click
import requests

from collections import defaultdict
from datetime import date, datetime, timedelta
from typing import Literal, Optional, NamedTuple

from pydantic import BaseModel, TypeAdapter, ConfigDict
from pydantic.alias_generators import to_camel


BASE_URL = "https://winbindex.m417z.com"
DATA = "data"
FILENAME_METADATA = "by_filename_compressed"
FILENAMES = "filenames.json"


class OSVersionInfo(NamedTuple):
    version: str
    build: int
    rss: str


WINDOWS_10_RSS = (
    "https://support.microsoft.com/en-us/feed/rss/6ae59d69-36fc-8e4d-23dd-631d98bf74a9"
)
WINDOWS_11_RSS = (
    "https://support.microsoft.com/en-us/feed/rss/4ec863cc-2ecd-e187-6cb3-b50c6545db92"
)

OS_VERSIONS_INFO = [
    OSVersionInfo("1507", 10240, WINDOWS_10_RSS),
    OSVersionInfo("1511", 10586, WINDOWS_10_RSS),
    OSVersionInfo("1607", 14393, WINDOWS_10_RSS),
    OSVersionInfo("1703", 15063, WINDOWS_10_RSS),
    OSVersionInfo("1709", 16299, WINDOWS_10_RSS),
    OSVersionInfo("1803", 17134, WINDOWS_10_RSS),
    OSVersionInfo("1809", 17763, WINDOWS_10_RSS),
    OSVersionInfo("1903", 18362, WINDOWS_10_RSS),
    OSVersionInfo("1909", 18363, WINDOWS_10_RSS),
    OSVersionInfo("2004", 19041, WINDOWS_10_RSS),
    OSVersionInfo("20H2", 19042, WINDOWS_10_RSS),
    OSVersionInfo("21H1", 19043, WINDOWS_10_RSS),
    OSVersionInfo("21H2", 19044, WINDOWS_10_RSS),
    OSVersionInfo("11-21H2", 22000, WINDOWS_11_RSS),
    OSVersionInfo("22H2", 19044, WINDOWS_10_RSS),
    OSVersionInfo("11-22H2", 22621, WINDOWS_11_RSS),
    OSVersionInfo("11-23H2", 22631, WINDOWS_11_RSS),
    OSVersionInfo("11-24H2", 26100, WINDOWS_11_RSS),
]

OS_VERSIONS = [v.version for v in OS_VERSIONS_INFO]


class FileInfo(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True,
    )
    size: int
    md5: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None
    machine_type: int
    timestamp: int
    virtual_size: int
    version: Optional[str] = None
    description: Optional[str] = None
    signing_status: Optional[Literal["Signed", "Unsigned", "Unknown"]] = None
    signature_type: Optional[Literal["Overlay", "Catalog file"]] = None
    signing_date: Optional[list[datetime]] = None


class UpdateInfo(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True,
    )
    heading: Optional[str] = None
    release_date: date
    release_version: str
    update_url: str


class AssemblyIdentity(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True,
    )
    build_type: str
    language: str
    name: str
    processor_architecture: str
    public_key_token: str
    version: str
    version_scope: str


class AssemblyAttributes(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True,
    )
    destination_path: str
    import_path: str
    name: str
    source_name: str
    source_path: str


class Assembly(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True,
    )
    assembly_identity: AssemblyIdentity
    attributes: list[AssemblyAttributes]


class WindowsVersion(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True,
    )
    assemblies: dict[str, Assembly]
    update_info: UpdateInfo


class WindowsVersionInfo(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True,
    )
    iso_sha1: Optional[str] = None
    iso_sha256: Optional[str] = None
    release_date: date


class BaseVersion(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True,
    )
    source_paths: list[str]
    windows_version_info: WindowsVersionInfo


class FileMetaData(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True,
    )
    file_info: FileInfo
    windows_versions: dict[str, dict[str, BaseVersion | WindowsVersion]]


FileMetaDatas = TypeAdapter(dict[str, FileMetaData])


def _get_file_info(name: str) -> list[dict[str, str]]:
    return gzip.decompress(
        requests.get(f"{BASE_URL}/{DATA}/{FILENAME_METADATA}/{name}.json.gz").content
    )


def get_file_info(name: str) -> dict[str, FileMetaData]:
    return FileMetaDatas.validate_json(_get_file_info(name))


def get_filenames() -> list[str]:
    return json.loads(
        requests.get(f"{BASE_URL}/{DATA}/{FILENAME_METADATA}/{FILENAMES}").content
    )


@click.group()
@click.version_option()
def cli():
    "windows binary index"


def by_version(
    metadatas: dict[str, FileMetaData]
) -> dict[str, dict[str, dict[date, FileMetaData]]]:
    metadata_by_version = {
        "x64": defaultdict(dict),
        "x86": defaultdict(dict),
    }
    for k, metadata in metadatas.items():
        for os_version, patch_info in metadata.windows_versions.items():
            for _, version in patch_info.items():
                if isinstance(version, BaseVersion):
                    release_date = version.windows_version_info.release_date
                    arch = (
                        "x86"
                        if "wow" in [x.lower() for x in version.source_paths]
                        else "x64"
                    )
                elif isinstance(version, WindowsVersion):
                    release_date = version.update_info.release_date
                    arch = (
                        "x86"
                        if next(
                            iter(version.assemblies.values())
                        ).assembly_identity.processor_architecture
                        == "wow64"
                        else "x64"
                    )
                else:
                    raise TypeError()

                metadata_by_version[arch][os_version][release_date] = metadata

    return metadata_by_version


def current_month():
    return date.today().strftime("%m.%y")


def get_patch_tuesday(month):
    month, year = [int(x) for x in month.split(".")]
    start = date(2000 + year, month, 1)
    return timedelta(days=7 + (1 - start.weekday()) % 7) + start


def get_download_link(filename, timestamp, imagesize):
    file_id = f"{timestamp:08x}".upper() + f"{imagesize:x}".lower()
    return (
        "https://msdl.microsoft.com/download/symbols/"
        + filename
        + "/"
        + file_id
        + "/"
        + filename
    )


def download_file(filename: str, metadata: FileMetaData) -> bytes:
    link = get_download_link(
        filename, metadata.file_info.timestamp, metadata.file_info.virtual_size
    )
    return requests.get(link).content


def download_before_after(filename, output_dir, os_ver, month, bitness):
    metadatas = get_file_info(filename)
    metadatas_by_version = by_version(metadatas)

    selected_os_files = metadatas_by_version[bitness][os_ver]

    sorted_files = sorted(selected_os_files.items(), key=lambda k: k[0])

    patch_tuesday = get_patch_tuesday(month)

    before = next(file for (d, file) in sorted_files[::-1] if d < patch_tuesday)
    after = next(file for (d, file) in sorted_files if d >= patch_tuesday)

    p = pathlib.Path(output_dir)
    p.mkdir(exist_ok=True)

    before_dir = p / "before"
    after_dir = p / "after"

    before_dir.mkdir(exist_ok=True)
    after_dir.mkdir(exist_ok=True)

    # TODO: check if exists
    if not (before_dir / filename).exists():
        (before_dir / filename).write_bytes(download_file(filename, before))
    if not (after_dir / filename).exists():
        (after_dir / filename).write_bytes(download_file(filename, after))


def export_diaphora(path):
    import ida

    db_file = path + ".sqlite3"
    if pathlib.Path(db_file).exists():
        return

    ida.open_database(path, run_auto_analysis=True)

    os.putenv("DIAPHORA_CPU_COUNT", "1")
    os.putenv("DIAPHORA_AUTO", "1")
    os.putenv("DIAPHORA_LOG_PRINT", "1")
    os.putenv("DIAPHORA_EXPORT_FILE", db_file)
    os.putenv("DIAPHORA_USE_DECOMPILER", "1")
    os.putenv("PYTHONWARNINGS", "ignore")

    diaphora_script = pathlib.Path.home() / "tools" / "diaphora" / "diaphora_ida.py"

    run_script(str(diaphora_script))
    ida.close_database()

sys.path.append("/home/gilad/idapro-9.0/python/3/")
sys.path.append("/home/gilad/idapro-9.0/python/3/ida_64")
sys.path.append("/home/gilad/idapro-9.0/plugins")
import ida_idaapi


def run_script(script_file_name: str):
    assert os.path.isfile(script_file_name)
    ida_idaapi.IDAPython_ExecScript(
        script_file_name, globals() | {"__name__": "__main__"}
    )


def diff_diaphora(output_dir, filename, before_db, after_db):
    subprocess.check_call(
        [
            sys.executable,
            str(pathlib.Path.home() / "tools/diaphora/diaphora.py"),
            before_db,
            after_db,
            "-o",
            str(pathlib.Path(output_dir) / f"{filename}.diaphora"),
        ]
    )


def run_diaphora(filename, output_dir):
    before_db = str(pathlib.Path(output_dir) / "before" / f"{filename}")
    after_db = str(pathlib.Path(output_dir) / "after" / f"{filename}")
    export_diaphora(before_db)
    export_diaphora(after_db)
    export_diaphora_html(
        str(pathlib.Path(output_dir) / "before" / filename),
        str(pathlib.Path(output_dir) / "before" / f"{filename}.sqlite"),
        str(pathlib.Path(output_dir) / "after" / f"{filename}.sqlite"),
        str(pathlib.Path(output_dir) / f"{filename}_asm_{{func}}.html"),
        str(pathlib.Path(output_dir) / f"{filename}_pseudo_{{func}}.html"),
    )


def export_diaphora_html(idb, db_path1, db_path2, asm_diff, pseudo_diff):
    import ida

    ida.open_database(idb, run_auto_analysis=True)
    os.environ["DIAPHORA_DB_PATH1"] = db_path1
    os.environ["DIAPHORA_DB_PATH2"] = db_path2
    os.environ["DIAPHORA_PSEUDO_DIFF_PATH"] = pseudo_diff
    os.environ["DIAPHORA_ASM_DIFF_PATH"] = asm_diff
    run_script(str(pathlib.Path(__file__).parent / "myscript.py"))
    ida.close_database()


@cli.command(name="patchdiff")
@click.argument("filename")
@click.argument("output-dir")
@click.option(
    "--os-ver",
    default=OS_VERSIONS_INFO[-1].version,
    type=click.Choice(OS_VERSIONS),
    show_default=True,
)
@click.option("--month", default=current_month(), show_default=True)
@click.option(
    "--bitness", default="x64", show_default=True, type=click.Choice(["x64", "x86"])
)
def patchdiff(filename, output_dir, os_ver, month, bitness):
    download_before_after(filename, output_dir, os_ver, month, bitness)
    run_diaphora(filename, output_dir)


from xml.etree import ElementTree as ET


@cli.command(name="listdiff")
@click.option(
    "--os-ver",
    default=OS_VERSIONS_INFO[-1].version,
    type=click.Choice(OS_VERSIONS),
    show_default=True,
)
@click.option("--month", default=current_month(), show_default=True)
@click.option(
    "--bitness", default="x64", show_default=True, type=click.Choice(["x64", "x86"])
)
def listdiff(os_ver, month, bitness):
    version = next(v for v in OS_VERSIONS_INFO if v.version == os_ver)
    rss = ET.XML(requests.get(version.rss).text)

    kbs = parse_kbs(rss)[version.build]
    patch_tuesday = get_patch_tuesday(month)

    before = next(link for (d, kb, link) in kbs[::-1] if d < patch_tuesday)
    after = next(link for (d, kb, link) in kbs if d >= patch_tuesday)

    before_files = get_list_from_link(before)
    after_files = get_list_from_link(after)

    for file, version in sorted(after_files - before_files, key=operator.itemgetter(0)):
        print(f"{file} -> {version}")


kb_re = re.compile(
    r"(.* \d+, \d+)—KB(\d+) \(OS Build? (\d+\.\d+)(?: and (\d+\.\d+))*\)"
)


def parse_kbs(rss) -> dict[int, list[tuple[date, str, str]]]:
    kbs = defaultdict(list)
    for item in rss.findall(".//item"):
        title = item.find("title").text
        link = item.find("link").text
        # print(title)
        m = kb_re.match(title)
        if m:
            date_, kb, *versions = m.groups()
            date_ = datetime.strptime(date_, "%B %d, %Y")
            date_ = date(date_.year, date_.month, date_.day)
            for version in versions:
                if version is not None:
                    kbs[int(version.split(".")[0])].append((date_, kb, link))

    return {k: sorted(v, key=operator.itemgetter(0)) for (k, v) in kbs.items()}


def get_list_from_link(link):
    soup = bs4.BeautifulSoup(requests.get(link).text, "html.parser")
    csv_link = soup.findAll(
        "a", text=re.compile("file information for cumulative update \d+")
    )[0]["href"]
    data = io.StringIO(requests.get(csv_link).text)
    data.readline()
    return set((x["File name"], x["File version"]) for x in csv.DictReader(data))
