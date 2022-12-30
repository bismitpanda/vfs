import sys, tomlkit, subprocess

ver = sys.argv[1]

with open("Cargo.toml", "r+") as f:
    toml = tomlkit.load(f)
    toml["package"]["version"] = ver
    f.seek(0)
    tomlkit.dump(toml, f)

subprocess.call(["cargo", "build", "--release"])

with open("target/release/vfs.exe", "rb") as src, open("vfs.exe", "wb") as dst:
    dst.write(src.read())

subprocess.call(["cargo", "clean"])

with open('test.vfs', 'wb') as vfs:
    vfs.write(b'\x00' * 524292)


subprocess.call(["git", "add", "."])
subprocess.call(["git", "commit", "-m", f"v{ver}"])
subprocess.call(["git", "push"])