import sys
import os

sys.path.append("/home/gilad/tools/diaphora")


def export_diaphora_html(db_path1, db_path2, html_pseudo, html_asm):
    from diaphora_ida import CIDABinDiff
    from diaphora_config import DEFAULT_SCRIPT_PATCH_DIFF

    class MyCIDABinDiff(CIDABinDiff):
        def show_choosers(self):
            pass

    idbd = MyCIDABinDiff(db_path1)
    idbd.diff(db_path2)

    for result in idbd.interesting_matches.items:
        ea1, ea2 = result[1], result[3]
        name = result[2]
        idbd.save_pseudo_diff(ea1, ea2, html_pseudo.format(func=name[:10].replace(" ", "_")))
        idbd.save_asm_diff(ea1, ea2, html_asm.format(func=name[:10].replace(" ", "_")))

    for result in idbd.unmatched_primary.items:
        print(result)
        ea = result[1]
        proto = idbd.decompile_and_get(int(ea, 16))
        if not proto:
            continue
        buf1 = proto + "\n" + "\n".join(idbd.pseudo[int(ea, 16)])
        print(buf1)

if __name__ == "__main__":
    export_diaphora_html(
        os.environ["DIAPHORA_DB_PATH1"],
        os.environ["DIAPHORA_DB_PATH2"],
        os.environ["DIAPHORA_PSEUDO_DIFF_PATH"],
        os.environ["DIAPHORA_ASM_DIFF_PATH"],
    )
