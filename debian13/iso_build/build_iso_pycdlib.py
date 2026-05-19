#!/usr/bin/env python3
"""使用 pycdlib 生成可启动 ISO 镜像（genisoimage 不可用时的备选方案）"""
import os
import sys
import pycdlib

def build_iso(source_dir, output_iso):
    if not os.path.isdir(source_dir):
        print("错误: 源目录不存在: {}".format(source_dir))
        sys.exit(1)

    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=4, joliet=3, rock_ridge="1.09", vol_ident="GATEKEEPER")

    added_dirs = set()
    count = 0

    def ensure_dir(rel_dir):
        """确保目录及其父目录都已添加"""
        if rel_dir in added_dirs:
            return
        parts = rel_dir.split(os.sep)
        for i in range(1, len(parts) + 1):
            sub = os.sep.join(parts[:i])
            if sub in added_dirs:
                continue
            iso_upper = "/" + "/".join(p.upper().replace(".", "_").replace("-", "_") for p in parts[:i])
            joliet = "/" + "/".join(parts[:i])
            rr = parts[-1]
            try:
                iso.add_directory(iso_path=iso_upper, joliet_path=joliet, rr_name=rr)
                added_dirs.add(sub)
            except pycdlib.pycdlibexception.PyCdlibInvalidInput:
                added_dirs.add(sub)

    # 1. 添加所有目录
    for root, dirs, files in os.walk(source_dir):
        rel = os.path.relpath(root, source_dir)
        if rel != ".":
            ensure_dir(rel)

    # 2. 添加所有文件
    for root, dirs, files in os.walk(source_dir):
        for f in files:
            fp = os.path.join(root, f)
            if not os.path.isfile(fp):
                continue
            rel = os.path.relpath(fp, source_dir)
            parent = os.path.dirname(rel)
            if parent:
                ensure_dir(parent)
            parts = rel.split(os.sep)
            iso_upper = "/" + "/".join(p.upper().replace(".", "_").replace("-", "_") for p in parts)
            joliet = "/" + rel
            rr = f
            try:
                iso.add_file(fp, iso_path=iso_upper, joliet_path=joliet, rr_name=rr)
                count += 1
            except Exception as e:
                print("警告: 跳过 {}: {}".format(rel, e))

    # 3. 配置 El Torito 启动
    isolinux_bin = os.path.join(source_dir, "isolinux", "isolinux.bin")
    if os.path.isfile(isolinux_bin):
        iso_upper_bin = "/" + "ISOLINUX/ISOLINUX_BIN"
        try:
            iso.add_eltorito(iso_upper_bin, boot_info_table=True)
            print("  El Torito 启动已配置")
        except Exception as e:
            print("  警告: El Torito 配置失败: {}".format(e))

    iso.write(output_iso)
    iso.close()
    size = os.path.getsize(output_iso)
    print("ISO 生成完成: {} ({:.1f} MB, {} 个文件)".format(output_iso, size / 1048576, count))

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("用法: {} <源目录> <输出ISO>".format(sys.argv[0]))
        sys.exit(1)
    build_iso(sys.argv[1], sys.argv[2])
