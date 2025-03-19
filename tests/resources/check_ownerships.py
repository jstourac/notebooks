import grp
import logging
import os
import pwd
import stat
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

log = logging.getLogger(__name__)


def get_permissions(filepath):
    """Gets file permissions in human-readable format."""
    st = os.stat(filepath)
    mode = st.st_mode
    # print(f"mode: {oct(mode)}")

    # Get file type
    if stat.S_ISDIR(mode):
        file_type = "d"  # Directory
    elif stat.S_ISLNK(mode):
        file_type = "l"  # Symbolic link
    else:
        file_type = "-"  # Regular file

    # Get permissions
    permissions = ""
    for i in range(3):  # User, group, others
        shift = (2 - i) * 3
        permissions += (
            "r" if mode & (stat.S_IRUSR >> shift) else "-"
        ) + (
            "w" if mode & (stat.S_IWUSR >> shift) else "-"
        ) + (
            "x" if mode & (stat.S_IXUSR >> shift) else "-"
        )

    return file_type + permissions

def get_owner_group(filepath):
    """Gets file owner and group names."""
    st = os.stat(filepath)
    uid = st.st_uid
    gid = st.st_gid
    owner = pwd.getpwuid(st.st_uid).pw_name
    group = grp.getgrgid(st.st_gid).gr_name
    return uid, gid, owner, group

def check_file_info(filepath, expected_uid, expected_gid):
    """Check the file ownership and group match expectation."""
    ret_code = 0

    try:
        # Let's grab also file permissions that we can print in case of an error
        permissions = get_permissions(filepath)
        uid, gid, owner, group = get_owner_group(filepath)
        if uid != int(expected_uid) or gid != int(expected_gid):
            log.error(f"{permissions} {owner}:{group} {filepath} --- expected: {expected_uid}:{expected_gid}")
            ret_code = 1
        else:
            log.debug(f"{permissions} {owner}:{group} {filepath}")
    except FileNotFoundError:
        log.error(f"File not found: {filepath}")
        ret_code = 1
    except KeyError: #for cases when the UID/GID are not present in the system.
        st = os.stat(filepath)
        log.error(f"{get_permissions(filepath)} {st.st_uid}:{st.st_gid} {filepath}")
        ret_code = 1

    return ret_code

def iterate_directory(directory, expected_uid, expected_gid):
    """Iterates over the directory recursively and checks the ownership."""
    ret_code = 0
    log.info(f"Starting iteration over the {directory}")

    for root, _, files in os.walk(directory):
        ret_code += check_file_info(root, expected_uid, expected_gid)
        for file in files:
            filepath = os.path.join(root, file)
            ret_code += check_file_info(filepath, expected_uid, expected_gid)

    log.info(f"Check done. Number of found issues: {ret_code}")
    return ret_code

# Main part of the script execution
if __name__ == "__main__":
    if len(sys.argv) != 3:
        path_to_iterate = sys.argv[1]
        expected_uid = sys.argv[2]
        expected_gid = sys.argv[3]
    else:
        log.error("Please, specify the path you want to check and expected owner and group!")
        exit(1)

    log.info(f"Gonna check: {path_to_iterate}; expected ownership is: {expected_uid}:{expected_gid}")

    ret_code = iterate_directory(path_to_iterate, expected_uid, expected_gid)
    exit(ret_code)
