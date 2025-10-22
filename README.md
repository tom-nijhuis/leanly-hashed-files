# Leanly Hashed - File database with efficient duplicate detection.

A high-performance Python library for scanning directories, hashing files, and detecting duplicates with optimization strategies.

## Features

- **Multithreaded file processing**: reducing file IO bottlenecks
- **Lean hashing methodology**: only calculating partial file hashes for potential duplicates
- **Automatic hash upgrading**: upgrade to full file hash when potential duplicates are found
- **Memory-efficient** real-time hash dictionary maintenance
- **Comprehensive file statistics** and duplicate analysis
- **Robust error handling** and progress reporting


## Performance Optimizations

-  Multithreaded Processing
-  Chunked File Reading
-  Real-time Cache Management and two-stage duplicate detection
    - Stage one: only hash the first 1MB of a file to detect potential duplicates. 
    - Verify potential duplicates by calculating full hash on relevant files only


### Hash type Classification

The database tracks hash completeness with explicit types:

- **`"full"`**: Complete file has been hashed
- **`"head_1MB"`**: Only first 1MB has been hashed


## File Information Structure

Each file entry contains comprehensive metadata:

```python
{
    "path": "/path/to/file.txt",
    "folder": "/path/to"
    "hash": "sha256_hash_string",
    "hash_type": "full",  # or "head_1MB"
    "size": 1048576,
    "size_formatted": "1.0 MB",
    "created": 1634567890.123,
    "modified": 1634567891.456,
    "success": True
}
```


## Statistics and Analysis

Comprehensive statistics for duplicate analysis:

```python
stats = db.get_stats()
print(stats)
# {
#     'total_files': 10000,
#     'successful_files': 9995,
#     'failed_files': 5,
#     'total_size': 1073741824,
#     'total_size_formatted': '1.0 GB',
#     'duplicate_hashes': {...},
#     'total_duplicate_size': 536870912
# }
```

## Limitations

- **Network drives**: May be slower due to latency
- **Many small files (<1MB)**: We still read the complete contents. Additional IO for file walk
- **Extremely large files**: Full hash calculation can be time-consuming. Consider increasing head size
- **Memory usage**: Large datasets require sufficient RAM for hash dictionary. Writing intermediate state to disc is not implemented.

## Process Flow

```
For each file:
     Read file metadata (size, timestamps)
     Calculate hash
        If file_size <= head_size → hash_type = "full"
        If file_size > head_size → hash_type = "head_1MB"
     Check for existing hash in cache:
        If found AND current hash_type != "full":
               Upgrade all file entries with this hash to full hash
               Remove old hash entries from cache
            Add updated entries with full hashes
        If not found OR already full:
            Add to cache normally
```
