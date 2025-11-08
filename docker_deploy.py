# docker_deploy_
# Interactive Docker deploy script
#!/usr/bin/env python3
import os
import sys
import time
import subprocess
import getpass
from pathlib import Path

try:
    import paramiko
    from scp import SCPClient
except Exception as e:
    print("Missing Python dependencies: paramiko and scp are required.")
    print("Install them inside a virtualenv:")
    print("  python3 -m venv venv")
    print("  source venv/bin/activate")
    print("  pip install paramiko scp")
    sys.exit(1)


def run_cmd(cmd, capture_output=False, check=False):
    if isinstance(cmd, (list, tuple)):
        pass
    else:
        # prefer shell for complex commands, but pass list when available
        cmd = cmd
    print(f">>> Running: {cmd}")
    res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE if capture_output else None,
                         stderr=subprocess.PIPE if capture_output else None, text=True)
    if capture_output:
        return res.returncode, res.stdout.strip(), res.stderr.strip()
    if check and res.returncode != 0:
        raise RuntimeError(f"Command failed: {cmd}\nExit code: {res.returncode}") 
    return res.returncode


def container_exists(identifier):
    code, out, err = run_cmd(f"docker ps -a --format '{{{{.ID}}}} {{{{.Names}}}}' | grep -w {identifier} || true", capture_output=True)
    # If grep returns no lines, out will be empty string
    return bool(out.strip())


def ask(prompt, default=None):
    if default:
        return input(f"{prompt} [{default}]: ").strip() or default
    return input(f"{prompt}: ").strip()


def timestamp():
    return time.strftime("%Y%m%d-%H%M%S")


def create_image_from_container(container_id_or_name, image_name):
    image_tag = f"{image_name}:{timestamp()}"
    cmd = f"docker commit {container_id_or_name} {image_tag}"
    rc = run_cmd(cmd)
    if rc != 0:
        raise RuntimeError("docker commit failed. Make sure container exists and you have permissions.")
    return image_tag


def save_image_to_tar(image_tag, archive_path):
    cmd = f"docker save -o {archive_path} {image_tag}"
    rc = run_cmd(cmd)
    if rc != 0:
        raise RuntimeError("docker save failed. Make sure the image exists.")


def create_ssh_client(host, port, username, password=None, pkey_path=None, timeout=30):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    if pkey_path:
        key = None
        try:
            key = paramiko.RSAKey.from_private_key_file(pkey_path)
        except Exception:
            try:
                key = paramiko.Ed25519Key.from_private_key_file(pkey_path)
            except Exception as e:
                raise RuntimeError(f"Failed to load private key: {e}")
        ssh.connect(hostname=host, port=port, username=username, pkey=key, timeout=timeout)
    else:
        ssh.connect(hostname=host, port=port, username=username, password=password, timeout=timeout)
    return ssh


def scp_put(ssh_client, local_path, remote_path):
    with SCPClient(ssh_client.get_transport()) as scp:
        scp.put(local_path, remote_path)


def remote_deploy_commands(remote_archive_path, container_name, image_tag, run_options):
    # Compose server-side commands. Keep them simple and safe.
    cmds = []
    cmds.append(f"docker load -i {remote_archive_path}")
    # Stop & remove old container if exists
    cmds.append(f"docker ps -a --format '{{{{.Names}}}}' | grep -w {container_name} && docker stop {container_name} && docker rm {container_name} || true")
    # Run the new container using the image tag created locally
    # image_tag is present on the server after docker load
    cmds.append(f"docker run -d --name {container_name} {run_options} {image_tag}")
    return " && ".join(cmds)


def main():
    print("Interactive Docker → Server deploy script")
    # Ask for container id/name
    container = ask("Enter local Docker container ID or name")
    if not container:
        print("Container identifier required. Exiting.")
        sys.exit(1)

    # Optionally validate container exists locally (best-effort grep)
    print("Checking container locally (best-effort)...")
    # We won't strictly fail because grep pattern may not match; let docker commit provide final error
    # if not container_exists(container):
    #     print(f"Warning: Couldn't find container '{container}' in local docker ps -a listing. Proceeding anyway.")

    # Ask for archive filename base (without .tar). Add timestamp if user wants unique name.
    archive_base = ask("Enter base name for the archive file (no extension). Leave empty to use 'image'")
    if not archive_base:
        archive_base = "image"
    unique_choice = ask("Add timestamp to filename to avoid collisions? (y/n)", "y").lower()
    if unique_choice.startswith("y"):
        archive_name = f"{archive_base}-{timestamp()}.tar"
    else:
        archive_name = f"{archive_base}.tar"
        # if file exists, ask for overwrite
        if Path(archive_name).exists():
            overwrite = ask(f"{archive_name} exists locally. Overwrite? (y/n)", "n").lower()
            if not overwrite.startswith("y"):
                print("Choose a different base name or allow timestamp. Exiting.")
                sys.exit(1)

    # Create image from container
    print(f"Committing container '{container}' to image...")
    try:
        image_tag = create_image_from_container(container, archive_base)
    except Exception as e:
        print(f"[ERROR] Failed to create image: {e}")
        sys.exit(1)
    print(f"[OK] Image created with tag: {image_tag}")

    # Save image to tar
    archive_path = str(Path.cwd() / archive_name)
    print(f"Saving image to archive file: {archive_path}")
    try:
        save_image_to_tar(image_tag, archive_path)
    except Exception as e:
        print(f"[ERROR] Failed to save image: {e}")
        sys.exit(1)
    print(f"[OK] Saved to {archive_path}")

    # Ask server credentials
    server_host = ask("Server IP or hostname")
    if not server_host:
        print("Server required. Exiting.")
        sys.exit(1)
    server_port = ask("Server SSH port", "22")
    try:
        server_port = int(server_port)
    except ValueError:
        server_port = 22
    server_user = ask("Server username", getpass.getuser())

    auth_choice = ask("Authenticate with password or private key? (password/key)", "password").lower()
    server_password = None
    pkey_path = None
    if auth_choice.startswith("k"):
        pkey_path = ask("Path to private key file (e.g. /home/user/.ssh/id_rsa)")
        if not Path(pkey_path).expanduser().exists():
            print("Private key file not found. Exiting.")
            sys.exit(1)
        pkey_path = str(Path(pkey_path).expanduser())
    else:
        server_password = getpass.getpass("Server password: ")

    remote_dir = ask("Remote directory to upload archive to", "/tmp")
    remote_archive_path = f"{remote_dir.rstrip('/')}/{archive_name}"
    container_name_remote = ask("Name to give the container on the server", container)
    print("Specify docker run additional options (e.g. -p 80:80 -e ENV=prod). Leave empty for none.")
    run_options = ask("docker run options", "")

    # Connect via SSH and transfer file
    print(f"Connecting to {server_user}@{server_host}:{server_port} ...")
    try:
        ssh = create_ssh_client(server_host, server_port, server_user, password=server_password, pkey_path=pkey_path)
    except Exception as e:
        print(f"[ERROR] SSH connection failed: {e}")
        sys.exit(1)

    print(f"Uploading {archive_path} to {server_host}:{remote_archive_path} ...")
    try:
        scp_put(ssh, archive_path, remote_archive_path)
    except Exception as e:
        print(f"[ERROR] SCP upload failed: {e}")
        ssh.close()
        sys.exit(1)
    print("[OK] Upload complete. Running remote deployment commands...")

    # Run remote commands
    cmds = remote_deploy_commands(remote_archive_path, container_name_remote, image_tag, run_options)
    try:
        stdin, stdout, stderr = ssh.exec_command(cmds)
        out = stdout.read().decode()
        err = stderr.read().decode()
        print("--- REMOTE STDOUT ---")
        print(out)
        print("--- REMOTE STDERR ---")
        print(err)
    except Exception as e:
        print(f"[ERROR] Remote command execution failed: {e}")
        ssh.close()
        sys.exit(1)

    print("[✅] Remote deploy commands finished. Check container with: docker ps -a on the server.")
    ssh.close()


if __name__ == "__main__":
    main()
            
