#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import sys
import tempfile
import zipfile
from argparse import Namespace
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from random import randint
from typing import Any, Dict, List

from loguru import logger


def chunk_reader(fobj, chunk_size=1024):
    """Generator that reads a file in chunks of bytes"""
    while True:
        chunk = fobj.read(chunk_size)
        if not chunk:
            return
        yield chunk


def get_hash(filename, first_chunk_only=False, hash=hashlib.sha1):
    hashobj = hash()
    file_object = open(filename, "rb")

    if first_chunk_only:
        hashobj.update(file_object.read(1024))
    else:
        for chunk in chunk_reader(file_object):
            hashobj.update(chunk)
    hashed = hashobj.digest()

    file_object.close()
    return hashed


def check_for_duplicates(paths, hash=hashlib.sha1):
    hashes_by_size = defaultdict(
        list
    )  # dict of size_in_bytes: [full_path_to_file1, full_path_to_file2, ]
    hashes_on_1k = defaultdict(
        list
    )  # dict of (hash1k, size_in_bytes): [full_path_to_file1, full_path_to_file2, ]
    hashes_full = {}  # dict of full_file_hash: full_path_to_file_string
    stats = {
        "duplicates": 0,
        "files": 0,
        "duplicates_deleted": 0,
        "small_hashed": 0,
        "full_hashed": 0,
    }
    logger.info(f"Checking paths: {paths}")
    for path in paths:
        for dirpath, dirnames, filenames in os.walk(path):
            # get all files that have the same size - they are the collision candidates
            for filename in filenames:
                full_path = os.path.join(dirpath, filename)
                try:
                    # if the target is a symlink (soft one), this will
                    # dereference it - change the value to the actual target file
                    full_path = os.path.realpath(full_path)
                    file_size = os.path.getsize(full_path)
                    hashes_by_size[file_size].append(full_path)
                except (OSError,):
                    # not accessible (permissions, etc) - pass on
                    continue

    found_files = sum([len(files) for size_in_bytes, files in hashes_by_size.items()])
    logger.info(f"Found {found_files} files with the same size")
    stats["files"] = found_files

    logger.info("Small Hashing files...")
    small_hashed_files = 0
    # For all files with the same file size, get their hash on the 1st 1024 bytes only
    for size_in_bytes, files in hashes_by_size.items():
        if len(files) < 2:
            continue  # this file size is unique, no need to spend CPU cycles on it

        for filename in files:
            try:
                small_hash = get_hash(filename, first_chunk_only=True)
                small_hashed_files += 1
                # the key is the hash on the first 1024 bytes plus the size - to
                # avoid collisions on equal hashes in the first part of the file
                # credits to @Futal for the optimization
                hashes_on_1k[(small_hash, size_in_bytes)].append(filename)
            except (OSError,):
                # the file access might've changed till the exec point got here
                continue

    found_files = sum([len(files) for small_hash, files in hashes_on_1k.items()])
    logger.info(f"Found {found_files} files with the same size and hash")
    stats["small_hashed"] = small_hashed_files

    full_hash_files = 0
    logger.info("Full Hashing files...")
    # For all files with the hash on the 1st 1024 bytes,
    # get their hash on the full file - collisions will be duplicates
    for __, files_list in hashes_on_1k.items():
        if len(files_list) < 2:
            # this hash of fist 1k file bytes is unique,
            # no need to spend cpy cycles on it
            continue

        for filename in files_list:
            try:
                full_hash = get_hash(filename, first_chunk_only=False)
                full_hash_files += 1
                try:
                    hashes_full[full_hash].append(
                        {
                            "filename": filename,
                            "path": filename,
                            "filename_len": len(Path(filename).parts),
                            "hash": full_hash,
                        }
                    )
                except Exception:
                    hashes_full[full_hash] = [
                        {
                            "filename": filename,
                            "path": filename,
                            "filename_len": len(Path(filename).parts),
                            "hash": full_hash,
                        }
                    ]

            except (OSError,):
                # the file access might've changed till the exec point got here
                continue

    stats["full_hashed"] = full_hash_files

    duplicates_deleted = 0
    logger.info("Deleting duplicates...")
    for key, item in hashes_full.items():
        logger.info(
            f"Duplicate Hash: {key} "
            f"| Files: {'\n'.join([_["filename"] for _ in item])}"
        )
        all_files_of_hash = sorted(item, key=lambda x: x["filename_len"])
        logger.info(f"Shortest path: {all_files_of_hash[0]['path']}")
        logger.info("Deleting the rest of the files...")
        for path in all_files_of_hash[1:]:
            logger.info(f"Deleting {path['path']}")
            Path(path["path"]).unlink()
            duplicates_deleted += 1
    logger.info(f"Deleted {duplicates_deleted} duplicates")
    stats["duplicates_deleted"] = duplicates_deleted
    return stats


def find_copy_files_by_ext(
    paths: List[Path],
    keep_folders=False,
    append_name=False,
    file_types: List[str] = None,
    output_path: Path = None,
    exclude_folders: List[str] = None,
    rename: bool = True,
) -> Dict[str, Any]:
    """Find and copy files, renaming them based on metadata."""
    stats = {
        "run_info": {
            "paths": paths,
            "keep_folders": keep_folders,
            "append_name": append_name,
            "file_types": file_types,
            "output_path": output_path,
            "exclude_folders": exclude_folders,
        },
        "stats": {"total_files": 0, "errors": []},
        "affected_files": [],
    }

    if output_path:
        output_path = Path(output_path)
    else:
        raise ValueError("Output path is required")

    output_path.mkdir(exist_ok=True)

    for path in paths:
        logger.info(f"Processing path: {path}")
        _process_directory(
            path=path,
            keep_folders=keep_folders,
            append_name=append_name,
            file_types=file_types,
            output_path=output_path,
            exclude_folders=exclude_folders,
            stats=stats,
            rename=rename,
        )

    return stats


def _process_directory(
    path: Path,
    keep_folders: bool,
    append_name: bool,
    file_types: List[str],
    output_path: Path,
    exclude_folders: List[str],
    stats: Dict[str, Any],
    zip_path: Path = None,
    rename: bool = True,
):
    """Process files in a directory."""
    for dirpath, dirnames, filenames in os.walk(path):
        for filename in filenames:
            full_path = Path(dirpath) / filename
            if file_types and full_path.suffix not in file_types:
                continue
            if exclude_folders and any(
                exclude_folder in full_path.parts for exclude_folder in exclude_folders
            ):
                continue
            if full_path.suffix == ".zip":
                try:
                    with tempfile.TemporaryDirectory() as temp_dir:
                        temp_path = Path(temp_dir)
                        with zipfile.ZipFile(full_path, "r") as zip_ref:
                            zip_ref.extractall(temp_path)

                        _process_directory(
                            path=temp_path,
                            append_name=True,
                            keep_folders=True,
                            file_types=file_types,
                            output_path=output_path,
                            exclude_folders=exclude_folders,
                            stats=stats,
                            zip_path=Path(full_path.parent, full_path.stem),
                        )
                    continue
                except Exception as e:
                    logger.error(f"Error processing zip file {full_path}: {e}")
                    stats["stats"]["errors"].append(
                        {"file": full_path, "error": str(e)}
                    )
                    continue

            try:
                base_path = output_path

                if keep_folders:
                    if zip_path:
                        base_path = output_path.joinpath(zip_path)
                    else:
                        base_path = base_path / full_path.relative_to(path).parent
                else:
                    base_path = output_path

                if rename:
                    create_date = datetime.fromtimestamp(full_path.stat().st_ctime)
                    modified_date = datetime.fromtimestamp(full_path.stat().st_mtime)

                    create_date_string = (
                        f"Create-{create_date.strftime('%Y-%m-%d_%H-%M-%S')}"
                    )
                    modified_date_string = (
                        f"Mod-{modified_date.strftime('%Y-%m-%d_%H-%M-%S')}"
                    )
                    size_string = (
                        f"Size-{int(round(full_path.stat().st_size / 1024, 0))}KB"
                    )
                    creator = (
                        f"User-{full_path.stat().st_uid}-{full_path.stat().st_gid}"
                    )

                    new_file_name = (f"{create_date_string}__"
                                     f"{modified_date_string}__"
                                     f"{size_string}__"
                                     f"{creator}")
                    if append_name:
                        new_file_name = f"{new_file_name}__{full_path.stem}"

                    new_file_name = (
                        new_file_name.replace(".", "_").replace(" ", "_")
                        + full_path.suffix
                    )
                else:
                    new_file_name = f"{full_path.stem.replace(
                        ".", "_"
                    ).replace(
                        " ", "_"
                    )}{full_path.suffix}"

                new_file_path = base_path / new_file_name

                logger.info(f"Renaming {full_path} to {new_file_path}")
                new_file_path.parent.mkdir(exist_ok=True, parents=True)

                if new_file_path.exists():
                    logger.warning(f"File {new_file_path} already exists")
                    stats["stats"]["errors"].append(
                        {
                            "file": full_path,
                            "error": f"File {new_file_path} already exists",
                        }
                    )
                    new_file_path = (
                        new_file_path.parent
                        / f"{new_file_path.stem}_"
                          f"{randint(0, 100000)}"
                          f"{new_file_path.suffix}"
                    )
                    logger.info(f"Renaming {full_path} to {new_file_path}")

                new_file_path.write_bytes(full_path.read_bytes())

                stats["affected_files"].append({"old": full_path, "new": new_file_name})
                stats["stats"]["total_files"] += 1

            except OSError as e:
                logger.error(f"Error renaming {full_path}: {e}")
                stats["stats"]["errors"].append({"file": full_path, "error": str(e)})


def parse_args(args: List[str]) -> Namespace:
    parser = argparse.ArgumentParser(description="Clean up duplicate files by type")
    parser.add_argument(
        "paths", nargs="+", help="Paths to check for duplicates", type=Path
    )
    parser.add_argument(
        "--keep-folders", action="store_true", help="Keep the folder structure"
    )
    parser.add_argument(
        "--append-name",
        action="store_true",
        help="Append the original name to the new name",
    )
    parser.add_argument(
        "--file-types", nargs="+", help="File types to check for duplicates"
    )
    parser.add_argument(
        "--output-path", help="Path to output the sorted files", type=Path
    )
    parser.add_argument(
        "--exclude-folders", nargs="+", help="Folders to exclude from the search"
    )
    parser.add_argument("--stats_path", help="Path to output the stats", type=Path)
    return parser.parse_args(args)


def main(args: List[str]) -> Dict[str, Any]:
    args = parse_args(args)
    output_path = Path(args.output_path)

    if not output_path:
        raise ValueError("Output path is required")

    output_path.mkdir(exist_ok=True)

    copy_stats = find_copy_files_by_ext(
        output_path=output_path,
        paths=args.paths,
        keep_folders=args.keep_folders,
        append_name=args.append_name,
        file_types=args.file_types,
        exclude_folders=args.exclude_folders,
        rename=args.rename,
    )

    dedup_stats = check_for_duplicates([output_path])
    stats = {"copy_stats": copy_stats, "dedup_stats": dedup_stats}
    if args.stats_path:
        args.statspath.mkdir(exist_ok=True, parents=True)
        stats_file = args.stats_path.joinpath(f"{datetime.now(UTC)}_dedup_stats.json")
    else:
        stats_file = Path.home().joinpath(f"{datetime.now(UTC)}_dedup_stats.json")

    with open(stats_file, "w") as f:
        json.dump(stats, f)

    return stats


def run():
    args = sys.argv[1:]
    stats = main(args)
    logger.info(stats)
    return stats


if __name__ == "__main__":
    run()
