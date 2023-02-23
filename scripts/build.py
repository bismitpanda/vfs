import sys, tomlkit, subprocess, shutil

ver = sys.argv[1]

with open("Cargo.toml", "r+") as f:
    toml = tomlkit.load(f)
    toml["package"]["version"] = ver
    f.seek(0)
    tomlkit.dump(toml, f)

subprocess.run(["cargo", "build", "--release"])

with open("target/release/vfs.exe", "rb") as src, open("vfs.exe", "wb") as dst:
    dst.write(src.read())

shutil.rmtree("target/release")

subprocess.run(["git", "add", "."])
subprocess.run(["git", "commit", "-m", f"v{ver}"])
subprocess.run(["git", "push"])