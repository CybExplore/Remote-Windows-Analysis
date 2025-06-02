import fnmatch
import os


def delete_files_starting_with_00(directory):
    # Walk through all directories and files in the given directory
    for dirpath, dirnames, filenames in os.walk(directory):
        for filename in fnmatch.filter(
            filenames, "00*"
        ):  # Match files starting with '00'
            file_path = os.path.join(dirpath, filename)  # Get the full file path
            try:
                os.remove(file_path)  # Delete the file
                print(f"Deleted: {file_path}")
            except Exception as e:
                print(f"Error deleting {file_path}: {e}")


# Call the function with the current working directory
delete_files_starting_with_00(os.getcwd())
