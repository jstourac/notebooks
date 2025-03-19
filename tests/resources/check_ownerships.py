import grp
import os
import pwd
import stat
import sys

def get_permissions(filepath):
    """Gets file permissions in human-readable format."""
    st = os.stat(filepath)
    mode = st.st_mode
    print(f"mode: {oct(mode)}")

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
    owner = pwd.getpwuid(st.st_uid).pw_name
    group = grp.getgrgid(st.st_gid).gr_name
    return owner, group

def print_file_info(filepath):
    """Prints file permissions, owner, group, and path."""
    ret_code = 0

    try:
        permissions = get_permissions(filepath)
        owner, group = get_owner_group(filepath)
        if owner != "default" or group != "root":
            print(f"{permissions} {owner}:{group} {filepath}")
            ret_code = 1
    except FileNotFoundError:
        print(f"File not found: {filepath}")
    except KeyError: #for cases when the UID/GID are not present in the system.
        st = os.stat(filepath)
        print(f"{get_permissions(filepath)} {st.st_uid}:{st.st_gid} {filepath}")

    return ret_code

def iterate_directory(directory):
    """Iterates over the directory recursively and prints file info."""
    ret_code = 0
    print(f"Starting iteration over the {directory}")

    for root, _, files in os.walk(directory):
        ret_code += print_file_info(root) #print directory info
        for file in files:
            filepath = os.path.join(root, file)
            ret_code += print_file_info(filepath)

    print(f"Directory check done. Number of found issues: {ret_code}")
    return ret_code

# Example usage:
if __name__ == "__main__":
    if len(sys.argv) > 1:
        directory_to_iterate = sys.argv[1]
    else:
        directory_to_iterate = "." # TODO maybe rather exit 1

    iterate_directory(directory_to_iterate)
