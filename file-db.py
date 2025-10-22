#!python3

import os
import hashlib
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class FileDB(dict):
    """A dictionary-like class for managing file information with scanning capabilities."""
    
    def __init__(self, head_size_mb=1, max_workers=4):
        """
        Initialize FileDB.
        
        Args:
            head_size_mb (int): Size in MB to read from the beginning of each file for hashing.
                              If 0, reads the entire file.
            max_workers (int): Number of worker threads for parallel processing.
        """
        super().__init__()
        self.head_size_mb = head_size_mb
        self.max_workers = max_workers
        self._hash_dict_cache = {}
    
    def __setitem__(self, key, value):
        """Override to maintain hash dictionary when items are added/modified."""
        super().__setitem__(key, value)
        
        if not self._is_valid_file_info(value):
            return
            
        hash_value = value["hash"]
        
        # Check if this hash already exists (potential duplicate)
        if self._has_potential_duplicate(hash_value, value):
            self._handle_potential_duplicate(hash_value, value)
        else:
            self._add_to_hash_cache(hash_value, value)
    
    def _is_valid_file_info(self, value):
        """Check if the file info is valid for hash caching."""
        return (isinstance(value, dict) and 
                value.get("success") and 
                isinstance(value.get("hash"), str))
    
    def _has_potential_duplicate(self, hash_value, value):
        """Check if we have a potential duplicate that needs full hash calculation."""
        return (hash_value in self._hash_dict_cache and 
                value.get("hash_type") != "full")
    
    def _handle_potential_duplicate(self, hash_value, new_value):
        """Handle the case where we detected a potential duplicate."""
        
        files_to_rehash = self._hash_dict_cache.get(hash_value, []) + [new_value]
        original_group_length = len(files_to_rehash)
        
        # Calculate full hashes for all involved files
        full_hash_groups = {}
        for file_info in files_to_rehash:
            if file_info.get("hash_type") != "full":
                self._upgrade_to_full_hash(file_info)
            
            # Group by full hash to detect false positives
            full_hash = file_info.get("hash")
            full_hash_groups[full_hash] = full_hash_groups.get(full_hash, []) + [file_info["path"]]
            
        # Detect and log false positives
        if len(full_hash_groups) > original_group_length:
            logger.warning(f"The partial hash resulted in false positives: {original_group_length} files split into {len(full_hash_groups)} different full hashes.")
    
    def _upgrade_to_full_hash(self, file_info):
        """Upgrade a file's hash from head to full hash."""
        file_path = file_info["path"]
        full_hash, hash_type = self._get_file_hash(file_path, head_only=False)
        
        if full_hash:
            self._remove_from_old_hash_group(file_info)
            self._update_file_info_with_full_hash(file_info, full_hash, hash_type)
            self._add_to_hash_cache(full_hash, file_info)
    
    def _remove_from_old_hash_group(self, file_info):
        """Remove file info from its old hash group in the cache."""
        old_hash = file_info["hash"]
        if old_hash in self._hash_dict_cache:
            self._hash_dict_cache[old_hash] = [f for f in self._hash_dict_cache[old_hash] if f is not file_info]
            if not self._hash_dict_cache[old_hash]:
                del self._hash_dict_cache[old_hash]
    
    def _update_file_info_with_full_hash(self, file_info, full_hash, hash_type):
        """Update file info with the new full hash and update the main database."""
        file_info["hash"] = full_hash
        file_info["hash_type"] = hash_type
        super().__setitem__(file_info["path"], file_info)
    
    def _add_to_hash_cache(self, hash_value, file_info):
        """Add file info to the hash cache."""
        if hash_value not in self._hash_dict_cache:
            self._hash_dict_cache[hash_value] = []
        if file_info not in self._hash_dict_cache[hash_value]:
            self._hash_dict_cache[hash_value].append(file_info)

    
    def __delitem__(self, key):
        """Deletion is not implemented for FileDB."""
        raise NotImplementedError("Deletion of items is not implemented")
    
    def clear(self, *args, **kwargs):
        """clear is not implemented for FileDB."""
        raise NotImplementedError("clear() is not implemented")
    
    def update(self, *args, **kwargs):
        """Update is not implemented for FileDB."""
        raise NotImplementedError("update() is not implemented")

    def _get_file_hash(self, file_path, head_only=True):
        """
        Calculate the SHA256 hash of a file.
        
        Args:
            file_path (str): Path to the file
            head_only (bool): If True, hash only the head portion; if False, hash entire file
            
        Returns:
            tuple: (SHA256 hash as hexadecimal string, hash_type) or (None, None) if error
        """
        try:
            file_size = os.path.getsize(file_path)
            head_size_bytes = int(1024 * 1024 * self.head_size_mb)
            
            # Determine if we're effectively reading the full file
            if head_only and self.head_size_mb > 0:
                # If file is smaller than head size, we're reading the full file
                if file_size <= head_size_bytes:
                    hash_type = "full"
                else:
                    hash_type = f"head_{self.head_size_mb}MB"
            else:
                hash_type = "full"
            
            sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                if head_only and self.head_size_mb > 0:
                    # Read only the head portion (or full file if smaller)
                    data = f.read(head_size_bytes)
                    sha256.update(data)
                else:
                    # Read entire file in chunks
                    while True:
                        data = f.read(1024 * 1024)  # Read in 1MB chunks
                        if not data:
                            break
                        sha256.update(data)
            return sha256.hexdigest(), hash_type
        except Exception as e:
            hash_type = f"head_{self.head_size_mb}MB" if head_only else "full"
            logger.error(f"Error calculating {hash_type} hash for `{file_path}`: {e}")
            return None, None
    
    def _get_file_data(self, file_path):
        """Compute the SHA256 hash of the first N MB of a file, get file size, creation and modification date."""
        try:
            stat = os.stat(file_path)
            # Use unified hash function for head hash
            hash, hash_type = self._get_file_hash(file_path, head_only=True)
            
            if hash is None:
                raise Exception("Failed to calculate head hash")
                
            return {
                "path": file_path,
                "parent": os.path.dirname(file_path),
                "hash": hash,
                "hash_type": hash_type,  # Remark the type of hash used for this file
                "size": stat.st_size,
                "size_formatted": self.format_file_size(stat.st_size),
                "created": stat.st_ctime,
                "modified": stat.st_mtime,
                "success": True,
            }
        except Exception as e:
            logger.error(f"Error processing file `{file_path}`: {e}")
            return {
                "path": file_path,
                "parent": os.path.dirname(file_path),
                "hash": None,
                "hash_type": None,
                "size": None,
                "size_formatted": None,
                "created": None,
                "modified": None,
                "success": False,
                "error": str(e)
            }
    
    def scan_folder(self, directory):
        """
        Scan a directory and its subdirectories for files.
        
        Args:
            directory (str): Path to the directory to scan.
            progress_callback (callable, optional): Function to call with progress updates.
                                                   Should accept (current, total, elapsed_time).
        """
        file_count = 0
        total_file_size = 0
        total_files = sum(len(files) for _, _, files in os.walk(directory))  # Total files for progress tracking
        logger.info(f"Starting scan of `{directory}` (filecount: {total_files})")
        report_step = max(1, total_files // 200) * 10  # Report progress every 5% of total files

        start_time = datetime.now()

        file_count = 0
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            # Walk through the directory and prepare the thread pool.
            for root, _, files in os.walk(directory):
                for filename in files:
                    file_path = os.path.join(root, filename)
                    # Ignore symlinks
                    if not os.path.islink(file_path):
                        # Add file processing to the thread pool
                        futures.append(executor.submit(self._get_file_data, file_path))

            # Collect results and display progress
            for future in as_completed(futures):
                try:
                    file_info = future.result()
                    self[file_info["path"]] = file_info                    
                    total_file_size += file_info.get("size", 0)
                    # Progress reporting
                    if file_count % report_step == 0 and file_count>0:
                        elapsed_time = (datetime.now() - start_time).total_seconds()
                        percentage_done = (file_count / total_files) * 100
                        files_per_second = file_count / elapsed_time
                        total_gb = total_file_size / (1024**3)
                        gb_per_second = total_gb / elapsed_time

                        logger.info(f"[{percentage_done:>3.0f}%] Processed {file_count:>6}/{total_files} files ({total_gb:.1f} GB) in {elapsed_time:.1f}s ({gb_per_second:.2f} GB/s)")
                except Exception as e:
                    raise
                    logger.error(f"Error processing file: {e}")
                file_count += 1
    
    @property
    def by_hash(self):
        """Read-only property that returns a dictionary of files grouped by hash."""
        return self._hash_dict_cache
    
    
    def get_stats(self):
        """Get statistics about the scanned files."""
        total_files = len(self)
        successful_files = sum(1 for info in self.values() if info.get("success"))
        total_size = sum(info.get("size", 0) for info in self.values() if info.get("success"))
        duplicate_stats = {hash_val: {
                             'files':[f['path'] for f in files],
                             'count': len(files),
                             'group_size':sum(f['size'] for f in files),
                             'group_size_formatted':self.format_file_size(sum(f['size'] for f in files)),
                            } for hash_val, files in sorted(self.by_hash.items(), key=lambda kv: -kv[1][0]['size']) if len(files) > 1}
        return {
            'total_files': total_files,
            'successful_files': successful_files,
            'failed_files': total_files - successful_files,
            'total_size': total_size,
            'total_size_formatted': self.format_file_size(total_size),
            'duplicate_hashes': duplicate_stats,
            'total_duplicate_size': sum(stats['group_size'] for stats in duplicate_stats.values()),
            'total_duplicate_size_formatted': self.format_file_size(sum(stats['group_size'] for stats in duplicate_stats.values())),
        }

    
    @staticmethod
    def format_file_size(size_bytes):
        """Convert bytes to human readable format."""
        if size_bytes == 0:
            return "0 B"
        size_names = ["B", "KB", "MB", "GB", "TB"]
        i = 0
        while size_bytes >= 1024 and i < len(size_names) - 1:
            size_bytes /= 1024.0
            i += 1
        return f"{size_bytes:.1f} {size_names[i]}"


# Example usage
if __name__ == "__main__":

    directory_to_scan = '/Users/tnijhuis/Documents/Private/'  # Change this to your target directory
    # directory_to_scan = '/Volumes/Sandisk1TB/'
    # directory_to_scan = '/Volumes/Sandisk4TB/'
    
    # Create FileDB instance and scan the directory
    file_db = FileDB(head_size_mb=1, max_workers=4)  # Use head hash for initial scan
    file_db.scan_folder(directory_to_scan)
    
    # Get statistics
    stats = file_db.get_stats()
    import json
    with open('file_scan_stats.json', 'w') as f:
        json.dump(stats, f, indent=4)

    with open('file_db.json', 'w') as f:
        json.dump(file_db, f, indent=4)