import argparse
import concurrent
import os
import tempfile
import zipfile
from argparse import Namespace
import sys
from random import randint
from typing import List, Dict

from loguru import logger

from deduplicator import get_hash

from concurrent.futures import ProcessPoolExecutor

import shutil
from pathlib import Path


def copy_folder(src, dest):
    """
    Copies the entire contents of the source folder to the destination folder.
    If the destination folder does not exist, it will be created.

    :param src: Path to the source folder
    :param dest: Path to the destination folder
    """
    src_path = Path(src)
    dest_path = Path(dest)

    if not src_path.exists() or not src_path.is_dir():
        raise FileNotFoundError(
            f"Source folder '{src}' does not exist or is not a directory.")

    dest_path.mkdir(parents=True, exist_ok=True)

    for item in src_path.iterdir():
        dest_item = dest_path / item.name

        if item.is_dir():
            shutil.copytree(item, dest_item, dirs_exist_ok=True)
        else:
            shutil.copy2(item, dest_item)

    print(f"Contents copied from '{src}' to '{dest}'.")


def _process_directory(
    path: Path,
    output_path: Path,
    zip_path: Path = None,
):
    """Process files in a directory."""
    total_files_processed = 0
    for dirpath, dirnames, filenames in os.walk(path):
        for filename in filenames:
            full_path = Path(dirpath) / filename
            if full_path.suffix == ".zip":
                try:
                    with tempfile.TemporaryDirectory() as temp_dir:
                        temp_path = Path(temp_dir)
                        with zipfile.ZipFile(full_path, "r") as zip_ref:
                            zip_ref.extractall(temp_path)

                        _process_directory(
                            path=temp_path,
                            output_path=output_path,
                            zip_path=Path(full_path.parent, full_path.stem).relative_to(path),
                        )
                    continue
                except Exception as e:
                    logger.error(f"Error processing zip file {full_path}: {e}")
                    continue

            try:
                base_path = output_path

                if zip_path:
                    base_path = output_path.joinpath(zip_path)
                else:
                    base_path = base_path / full_path.relative_to(path).parent

                new_file_name = base_path / full_path.relative_to(path)
                new_file_path = new_file_name.parent
                new_file_path.mkdir(exist_ok=True, parents=True)

                if new_file_name.exists():
                    logger.warning(f"File {new_file_path} already exists")
                    new_file_name = (
                        new_file_path.parent
                        / f"{new_file_path.stem}_"
                          f"{randint(0, 100000)}"
                          f"{new_file_path.suffix}"
                    )

                new_file_name.write_bytes(full_path.read_bytes())
                total_files_processed += 1

            except OSError as e:
                logger.error(f"Error renaming {full_path}: {e}")

    return total_files_processed


def diffie(target: Path, comparator: Path, output: Path):
    # Copy Files
    # copy_folder(target, output)

    # Hash Target Files
    target_hashes = hash_dir(output)

    # Hash comparator files
    comparator_hashes = hash_dir(comparator)

    # Removed duplicates present in both comparator and target from target
    comparator_hashes_list = [comparator_hash["hash"] for comparator_hash in comparator_hashes]

    update_targets = []
    for target_hash in target_hashes:
        logger.info(f"Check file for duplication in comparator {target_hash['file']}")
        if target_hash["hash"] in comparator_hashes_list:
            target_hash["file"].unlink()
            logger.info(f"File {target_hash['file']} has duplicate hash and has been removed")
        else:
            update_targets.append(target_hash)


    # Deduplicate the target files
    deduplicated_hashes = list(set([h["hash"] for h in update_targets]))

    deduplicated_targets = [target["file"] for target in update_targets if target["hash"] in deduplicated_hashes]

    for original_target in update_targets:
        if not original_target["file"] in deduplicated_targets:
            original_target["file"].unlink()

    delete_empty_dirs(output)



def get_hash_formatted(filename: Path) -> Dict[str, Path] | None:
    try:
        output = {"hash": get_hash(filename), "file": filename}
    except Exception as e:
        logger.error(f"Error getting hash from {filename}: {e}")
        output = None
    return output


def hash_dir(output):
    target_files = []
    target_hashes = []

    logger.info(f"Collecting files for {output}")

    for root, dirs, files in os.walk(output):
        for file in files:
            target_files.append(Path(root, file))

    target_files_count = len(target_files)

    logger.info(f"Staring Process Pool for {target_files_count} files")

    with ProcessPoolExecutor(max_workers=10) as executor:
        logger.info(f"Submitting jobs for {target_files_count} files")
        futures = {executor.submit(get_hash_formatted,file): file for file in target_files}

        logger.info(f"Waiting for {target_files_count} files to be processed")
        prior_percent_done = 0
        for future in concurrent.futures.as_completed(futures):
            file = futures[future]
            try:
                result = future.result()
                if result is not None:
                    target_hashes.append(result)
            except Exception as e:
                logger.error(f"Error hashing {file}: {e}")
            else:
                percent_done = round(len(target_hashes) * 100 / target_files_count)
                if percent_done > prior_percent_done:
                    logger.success(f"{percent_done}% Complete Hashing {output}")
                    prior_percent_done = percent_done

    return target_hashes


def delete_empty_dirs(directory: Path):
    # Ensure the given path is a Path object
    directory = Path(directory)

    # Walk through the directory tree
    for dirpath in directory.rglob('*'):
        # Check if the current directory is empty
        if dirpath.is_dir() and not any(dirpath.iterdir()):
            print(f"Deleting empty directory: {dirpath}")
            dirpath.rmdir()  # Remove the empty directory

            # After deleting, check the parent directory recursively
            delete_empty_dirs(dirpath.parent)


def call_diffie(args: Namespace):
    diffie(target=args.target, comparator=args.comparator, output=args.output)


def cli(args: List[str]) -> Namespace:
    parser = argparse.ArgumentParser(description='Diffie Hash Algorithm')
    parser.add_argument('target', help='Target To Compare', type=Path)
    parser.add_argument('comparator', help='The Files to Compare The Target To', type=Path)
    parser.add_argument('output', help='Output Path', type=Path)
    parser.set_defaults(func=call_diffie)

    return parser.parse_args(args)


def main(args):
    parsed_args = cli(args)
    parsed_args.func(parsed_args)


def run():
    args = sys.argv[1:]
    main(args)


if __name__ == '__main__':
    run()