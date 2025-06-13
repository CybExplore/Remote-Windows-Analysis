import fnmatch
import os


def delete_migration_files_starting_with_00(base_directory):
    for dirpath, dirnames, filenames in os.walk(base_directory):
        # Check if we are inside a migrations folder
        if os.path.basename(dirpath) == "migrations":
            for filename in fnmatch.filter(filenames, "00*"):
                file_path = os.path.join(dirpath, filename)
                try:
                    os.chmod(file_path, 0o777)  # Optional: ensure deletable
                    os.remove(file_path)
                    print(f"Deleted: {file_path}")
                except PermissionError:
                    print(f"Permission denied: {file_path}")
                except Exception as e:
                    print(f"Error deleting {file_path}: {e}")


# Example usage:
delete_migration_files_starting_with_00(os.getcwd())
