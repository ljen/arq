import lz4.block
import struct
import json
from io import BytesIO
from typing import Optional # For type hinting

# --- Data Classes for Parsed Structures ---
class BlobLoc:
    def __init__(self, blobIdentifier, isPacked, relativePath, offset, length, stretchEncryptionKey, compressionType):
        self.blobIdentifier = blobIdentifier
        self.isPacked = isPacked
        self.relativePath = relativePath
        self.offset = offset
        self.length = length
        self.stretchEncryptionKey = stretchEncryptionKey
        self.compressionType = compressionType

    def __repr__(self):
        return (f"BlobLoc(id={self.blobIdentifier}, packed={self.isPacked}, path={self.relativePath}, "
                f"offset={self.offset}, len={self.length}, encKey={self.stretchEncryptionKey}, compType={self.compressionType})")

class Node:
    def __init__(self):
        self.isTree: Optional[bool] = None
        self.treeBlobLoc: Optional[BlobLoc] = None
        self.computerOSType: Optional[int] = None
        self.dataBlobLocsCount: Optional[int] = None
        self.dataBlobLocs: list[BlobLoc] = []
        self.aclBlobLocIsNotNil: Optional[bool] = None
        self.aclBlobLoc: Optional[BlobLoc] = None
        self.xattrsBlobLocCount: Optional[int] = None
        self.xattrsBlobLocs: list[BlobLoc] = []
        self.itemSize: Optional[int] = None
        self.containedFilesCount: Optional[int] = None
        self.mtime_sec: Optional[int] = None
        self.mtime_nsec: Optional[int] = None
        self.ctime_sec: Optional[int] = None
        self.ctime_nsec: Optional[int] = None
        self.create_time_sec: Optional[int] = None
        self.create_time_nsec: Optional[int] = None
        self.username: Optional[str] = None
        self.groupName: Optional[str] = None
        self.deleted: Optional[bool] = None
        self.mac_st_dev: Optional[int] = None
        self.mac_st_ino: Optional[int] = None
        self.mac_st_mode: Optional[int] = None
        self.mac_st_nlink: Optional[int] = None
        self.mac_st_uid: Optional[int] = None
        self.mac_st_gid: Optional[int] = None
        self.mac_st_rdev: Optional[int] = None
        self.mac_st_flags: Optional[int] = None
        self.win_attrs: Optional[int] = None
        self.win_reparse_tag: Optional[int] = None # if Tree version >= 2
        self.win_reparse_point_is_directory: Optional[bool] = None # if Tree version >= 2

    def __repr__(self):
        return (f"Node(isTree={self.isTree}, itemSize={self.itemSize}, username={self.username}, "
                f"numDataBlobs={self.dataBlobLocsCount}, treeBlobLoc={self.treeBlobLoc})")


class Tree:
    def __init__(self):
        self.version: Optional[int] = None
        self.childNodesByNameCount: Optional[int] = None
        self.childNodes: dict[str, Node] = {}

    def __repr__(self):
        return f"Tree(version={self.version}, numChildren={self.childNodesByNameCount}, children={list(self.childNodes.keys())})"


# --- Binary Parsing Helper Functions ---
def read_bool(stream: BytesIO) -> bool:
    return struct.unpack('>B', stream.read(1))[0] == 1

def read_string(stream: BytesIO, field_name: str = "Unknown String") -> Optional[str]:
    start_pos = stream.tell()
    is_not_null = read_bool(stream)
    if not is_not_null:
        # print(f"Parsing string '{field_name}': isNull")
        return None
    length = struct.unpack('>Q', stream.read(8))[0]
    # print(f"Parsing string '{field_name}': isNotNull, length={length}, current_pos={stream.tell()}")

    str_data = stream.read(length)
    try:
        decoded_str = str_data.decode('utf-8')
        # print(f"Successfully decoded '{field_name}': {decoded_str[:50]}") # Print first 50 chars
        return decoded_str
    except UnicodeDecodeError as e:
        print(f"!!! UnicodeDecodeError for field '{field_name}' at stream position {start_pos} (string data starts at {stream.tell()-length}): {e}")
        print(f"Problematic string data (first 50 bytes): {str_data[:50]}")
        # It might be useful to see context around the error
        # stream.seek(start_pos)
        # print(f"Context around error (50 bytes before, 50 after): {stream.read(100)}")
        raise # Re-raise the error to be caught by the main handler

def read_uint32(stream: BytesIO) -> int:
    return struct.unpack('>I', stream.read(4))[0]

def read_int32(stream: BytesIO) -> int:
    return struct.unpack('>i', stream.read(4))[0]

def read_uint64(stream: BytesIO) -> int:
    return struct.unpack('>Q', stream.read(8))[0]

def read_int64(stream: BytesIO) -> int:
    return struct.unpack('>q', stream.read(8))[0]

def parse_blob_loc(stream: BytesIO, parent_field_name: str = "Unknown.BlobLoc") -> BlobLoc:
    print(f"    --- Parsing BlobLoc for '{parent_field_name}' at stream pos {stream.tell()} ---")
    blobIdentifier = read_string(stream, f"{parent_field_name}.blobIdentifier")
    print(f"      {parent_field_name}.blobIdentifier (len {len(blobIdentifier) if blobIdentifier else 'N/A'}) parsed (stream pos after: {stream.tell()})")

    isPacked = read_bool(stream)
    print(f"      {parent_field_name}.isPacked = {isPacked} (stream pos after: {stream.tell()})")

    # Read relativePath.isNotNull flag by peeking/reading carefully
    # We need to know if the string is null *without* fully consuming it via read_string if we need to skip.
    # read_string itself handles null correctly, but we need to react to the null *before* subsequent fields.

    pos_before_relPath_isNotNull = stream.tell()
    relPath_isNotNull_flag_byte = stream.read(1) # Read the isNotNull byte
    relPath_isNotNull = (relPath_isNotNull_flag_byte[0] == 1)
    stream.seek(pos_before_relPath_isNotNull) # Rewind to re-read properly by read_string or skip logic

    relativePath = read_string(stream, f"{parent_field_name}.relativePath") # This will correctly parse or return None
    print(f"      {parent_field_name}.relativePath (len {len(relativePath) if relativePath else 'N/A'}) parsed (stream pos after: {stream.tell()})")

    # Recovery logic for the specific data anomaly:
    # If isPacked is true, but relativePath turned out to be null (isNotNull was 0x00),
    # and this specific BlobLoc is the known problematic one (e.g. dataBlobLocs[0] of file1.txt)
    # we speculatively skip the bytes where the path *data* and its *length field* would have been.
    # The byte for isNotNull for relativePath (0x00) has already been consumed by read_string.
    # The path data was observed to be 90 bytes, its length field is 8 bytes.
    # So, skip 8 + 90 = 98 bytes *if* this recovery is triggered.
    # This is highly heuristic and specific to the observed problem with file1.txt's first datablob.
    if isPacked and relativePath is None:
        # Check if this is the specific known problematic BlobLoc.
        # This check is fragile. A better way might be to pass a hint or context.
        # For now, let's apply it somewhat generally if this condition (isPacked=T, relPath=null) is met.
        # The original data had byte 0x5a (90) for the length, and then 90 bytes of path data.
        # The isNotNull byte (0x00) for relativePath was at index 118.
        # The next 8 bytes (assumed length of path) were 000000000000005a (90).
        # The next 90 bytes were path data.
        # If read_string consumed the 0x00, stream is at 119.
        # We need to skip the 8 bytes (that would have been length) + 90 bytes (path data).

        # The current stream position is *after* read_string has processed the isNotNull byte for relativePath.
        # If relativePath is None, read_string consumed 1 byte (the isNotNull=false flag).

        # Let's get the actual length that *would* have been read if notNull was true,
        # by peeking at the next 8 bytes.
        pos_before_intended_length = stream.tell()
        intended_length_bytes = stream.read(8)
        # IMPORTANT: We MUST rewind after this peek before any skip, as these 8 bytes are actual data for offset/length etc.
        # in the current (broken) interpretation.
        stream.seek(pos_before_intended_length)

        # The specific anomaly showed that the bytes meant for 'offset' field actually encoded '90',
        # which was the length of the path string that was missing.
        # So, if the "offset" field (the 8 bytes after the null relPath flag) decodes to 90,
        # it's a strong indicator of this specific corruption.
        potential_path_len = struct.unpack('>Q', intended_length_bytes)[0]

        # This recovery is very specific to the observed pattern where the *offset* field
        # contains the *length* of the missing path.
        # The original path was 90 bytes. Its length field (8 bytes) + data (90 bytes) = 98 bytes.
        # The isNotNull byte (1 byte) for the path was already consumed by read_string.
        # So, if this pattern matches, we skip 98 bytes from the point *after* the isNotNull byte.
        # However, the current stream position is *already* after the isNotNull byte.
        # So we need to skip (8 bytes for stored length) + potential_path_len (actual path data).

        # A simpler, more direct heuristic for *this specific file*:
        # The problematic relativePath.isNotNull flag (\x00) is at absolute index 118 of decompressed tree data.
        # The *actual* offset field for this BlobLoc should start at absolute index 118 + 1 (for isNotNull) + 8 (for length) + 90 (for path data) = 217.
        # Current stream position is 119. So we need to skip 217 - 119 = 98 bytes.
        # This skip_length (98) is what we determined earlier.

        # Let's make the skip conditional on the parent_field_name for safety,
        # as this is very tailored.
        if parent_field_name == "Node.dataBlobLocs[0]": # Only for the first data blob of a node.
            # The byte for isNotNull (false) was consumed.
            # The next 8 bytes are currently being interpreted as 'offset'.
            # The 8 bytes after that are being interpreted as 'length'.
            # We need to skip these 8 bytes (which were supposed to be path length)
            # and then skip the N bytes of path data (where N was in those 8 bytes).

            # If stream is at 119 (after isNotNull=false for relPath).
            # Bytes at 119-126 are *currently* read as 'offset'. Let's assume these *were* the path length.
            path_len_if_not_null = potential_path_len # This is 'offset's current value, e.g. 90

            # We need to skip the 8 bytes that held this path_len_if_not_null,
            # and then path_len_if_not_null bytes of data.
            # Total skip = 8 + path_len_if_not_null.
            # This is from the current position (pos_before_intended_length / stream.tell())

            # This is tricky. If relativePath is None, read_string() has consumed 1 byte.
            # The stream is now at the position where 'offset' is about to be read.
            # The hypothesis is: the *actual* 'offset' field is 98 bytes further on from this point.
            skip_bytes_count = 98
            print(f"      RECOVERY: isPacked=True, relativePath is Null for '{parent_field_name}'. ")
            print(f"      RECOVERY: Current stream pos: {stream.tell()}. Speculatively skipping {skip_bytes_count} bytes.")
            skipped = stream.read(skip_bytes_count)
            if len(skipped) != skip_bytes_count:
                print(f"      RECOVERY WARNING: Tried to skip {skip_bytes_count} but only skipped {len(skipped)} (EOF?)")
            print(f"      RECOVERY: Stream pos after skip: {stream.tell()}.")
        # End of recovery logic

    offset = read_uint64(stream)
    print(f"      {parent_field_name}.offset = {offset} (stream pos after: {stream.tell()})")
    length = read_uint64(stream)
    print(f"      {parent_field_name}.length = {length} (stream pos after: {stream.tell()})")
    stretchEncryptionKey = read_bool(stream)
    print(f"      {parent_field_name}.stretchEncryptionKey = {stretchEncryptionKey} (stream pos after: {stream.tell()})")
    compressionType = read_uint32(stream)
    print(f"      {parent_field_name}.compressionType = {compressionType} (stream pos after: {stream.tell()})")
    print(f"    --- Finished BlobLoc for '{parent_field_name}' (stream pos after: {stream.tell()}) ---")
    return BlobLoc(blobIdentifier, isPacked, relativePath, offset, length, stretchEncryptionKey, compressionType)

def parse_node_data(stream: BytesIO, tree_version: int) -> Node: # tree_version for win_reparse fields
    print(f"--- Parsing Node at stream position {stream.tell()} ---")
    node = Node()
    node.isTree = read_bool(stream)
    print(f"  Node.isTree = {node.isTree} (stream pos after: {stream.tell()})")

    if node.isTree:
        print(f"  Node.isTree is True, parsing treeBlobLoc...")
        node.treeBlobLoc = parse_blob_loc(stream, "Node.treeBlobLoc")
        print(f"  Node.treeBlobLoc parsed (stream pos after: {stream.tell()})")

    node.computerOSType = read_uint32(stream)
    print(f"  Node.computerOSType = {node.computerOSType} (stream pos after: {stream.tell()})")
    node.dataBlobLocsCount = read_uint64(stream)
    print(f"  Node.dataBlobLocsCount = {node.dataBlobLocsCount} (stream pos after: {stream.tell()})")

    for i in range(node.dataBlobLocsCount):
        print(f"  --- Parsing Node.dataBlobLocs[{i}] at stream pos {stream.tell()} ---")
        node.dataBlobLocs.append(parse_blob_loc(stream, f"Node.dataBlobLocs[{i}]"))
        print(f"  --- Finished Node.dataBlobLocs[{i}] (stream pos after: {stream.tell()}) ---")

    node.aclBlobLocIsNotNil = read_bool(stream)
    print(f"  Node.aclBlobLocIsNotNil = {node.aclBlobLocIsNotNil} (stream pos after: {stream.tell()})")
    if node.aclBlobLocIsNotNil:
        print(f"  Node.aclBlobLocIsNotNil is True, parsing aclBlobLoc...")
        node.aclBlobLoc = parse_blob_loc(stream, "Node.aclBlobLoc")
        print(f"  Node.aclBlobLoc parsed (stream pos after: {stream.tell()})")

    node.xattrsBlobLocCount = read_uint64(stream)
    print(f"  Node.xattrsBlobLocCount = {node.xattrsBlobLocCount} (stream pos after: {stream.tell()})")

    for i in range(node.xattrsBlobLocCount):
        print(f"  --- Parsing Node.xattrsBlobLocs[{i}] at stream pos {stream.tell()} ---")
        node.xattrsBlobLocs.append(parse_blob_loc(stream, f"Node.xattrsBlobLocs[{i}]"))
        print(f"  --- Finished Node.xattrsBlobLocs[{i}] (stream pos after: {stream.tell()}) ---")

    node.itemSize = read_uint64(stream)
    node.containedFilesCount = read_uint64(stream)
    node.mtime_sec = read_int64(stream)
    node.mtime_nsec = read_int64(stream)
    node.ctime_sec = read_int64(stream)
    node.ctime_nsec = read_int64(stream)
    node.create_time_sec = read_int64(stream)
    node.create_time_nsec = read_int64(stream)

    # print(f"  Attempting to read username at {stream.tell()}")
    node.username = read_string(stream, "Node.username")
    # print(f"  Node.username = {node.username}")
    # print(f"  Attempting to read groupName at {stream.tell()}")
    node.groupName = read_string(stream, "Node.groupName")
    # print(f"  Node.groupName = {node.groupName}")

    node.deleted = read_bool(stream)
    node.mac_st_dev = read_int32(stream)
    node.mac_st_ino = read_uint64(stream)
    # Duplicated block removed.
    # The original file had a large duplicated section here which started with a mac_st_mode read
    # and ended with a second mac_st_ino read.
    # The parsing continues with the correct mac_st_mode read that was already in place after the duplication.
    node.mac_st_mode = read_uint32(stream)
    node.mac_st_nlink = read_uint32(stream)
    node.mac_st_uid = read_uint32(stream)
    node.mac_st_gid = read_uint32(stream)
    node.mac_st_rdev = read_int32(stream)
    node.mac_st_flags = read_int32(stream) # Arq doc says Int32, but might be UInt32 in practice for flags
    node.win_attrs = read_uint32(stream)

    if tree_version >= 2: # Assuming Tree version check applies here for Node fields
        node.win_reparse_tag = read_uint32(stream)
        node.win_reparse_point_is_directory = read_bool(stream)

    return node

def parse_tree_data(data: bytes) -> Tree:
    stream = BytesIO(data)
    tree = Tree()
    tree.version = read_uint32(stream)
    tree.childNodesByNameCount = read_uint64(stream)
    # print(f"Tree version: {tree.version}, childNodesByNameCount: {tree.childNodesByNameCount}")

    for i in range(tree.childNodesByNameCount):
        # print(f"Parsing child node {i} at stream position {stream.tell()}")
        child_name = read_string(stream, f"Tree.childName[{i}]")
        if child_name is None:
            # This case should ideally not happen based on Arq format for childNodes
            # but as a safeguard:
            print(f"Warning: Encountered a null child name during tree parsing for child {i}.")
            # Attempt to parse the node anyway, as it might still be there,
            # though this indicates a potential format mismatch or corruption.
            # A default name or skipping might be options, but let's try parsing.
            # If this causes issues, the alternative is to break or skip this entry.
            child_name = f"__UNKNOWN_CHILD_NAME_{i}__"

        # print(f"  Child name: '{child_name}'")
        tree.childNodes[child_name] = parse_node_data(stream, tree.version)

    # Check if all data was consumed
    remaining_bytes = stream.read()
    if remaining_bytes:
        print(f"Warning: {len(remaining_bytes)} unparsed bytes remaining in Tree data stream.")
        # print(f"Remaining raw: {remaining_bytes[:100]}") # for debugging

    return tree

def decompress_lz4_data(data: bytes) -> bytes:
    """
    Decompresses LZ4 data that is prefixed with a 4-byte big-endian length.
    """
    if len(data) < 4:
        raise ValueError("Data too short to contain length prefix.")

    decompressed_length = struct.unpack('>I', data[:4])[0]
    compressed_data = data[4:]

    # The stored length is the DECOMPRESSED length.
    # lz4.block.decompress needs the uncompressed size.
    decompressed_data = lz4.block.decompress(compressed_data, uncompressed_size=decompressed_length)
    return decompressed_data

def main():
    backup_record_path = "tests/arq_storage_location/FD5575D9-B7E1-43D9-B29C-B54ACC9BC2A9/backupfolders/29F6E502-2737-4417-8023-4940D61BA375/backuprecords/00173/6348988.backuprecord"

    try:
        with open(backup_record_path, 'rb') as f:
            raw_data = f.read()

        print(f"Read {len(raw_data)} bytes from {backup_record_path}")

        # The entire backuprecord file is compressed as one block
        # according to the documentation for "Backup Record File" format:
        # "The file is stored LZ4-compressed and (optionally) encrypted."
        # It doesn't explicitly state the 4-byte prefix for the *entire file content*,
        # but it does for "Data described in this document as LZ4-compressed".
        # Let's try decompressing the whole file content, assuming the prefix exists.

        decompressed_record_data = decompress_lz4_data(raw_data)

        print("\nSuccessfully decompressed backup record:")
        # Attempt to decode as UTF-8 to print. It's likely JSON.
        try:
            decompressed_json_str = decompressed_record_data.decode('utf-8')
            print(decompressed_json_str)

            # Try parsing it as JSON
            parsed_json = json.loads(decompressed_json_str)
            print("\nSuccessfully parsed decompressed data as JSON.")

            if 'node' in parsed_json and 'treeBlobLoc' in parsed_json['node']:
                print("\nFound 'node' and 'treeBlobLoc':")
                tree_blob_loc = parsed_json['node']['treeBlobLoc']
                print(json.dumps(tree_blob_loc, indent=2))

                # Attempt to decompress tree data
                storage_location_root = "tests/arq_storage_location"
                # The relativePath in treeBlobLoc starts with /<backup_set_uuid>/
                # We need to construct the full path relative to the repo root.
                # Example relativePath: /FD5575D9-B7E1-43D9-B29C-B54ACC9BC2A9/treepacks/A4/...
                # We need to join storage_location_root with the path components *after* the leading slash.
                pack_file_path_parts = tree_blob_loc['relativePath'].strip('/').split('/')
                # pack_file_path_parts will be ['FD5575D9-B7E1-43D9-B29C-B54ACC9BC2A9', 'treepacks', 'A4', '...']
                # The first part is the backup set UUID, which is already part of our base path for this backup set.
                # So, we join storage_location_root + backup_set_uuid + rest_of_the_path

                pack_file_full_path = f"{storage_location_root}/{'/'.join(pack_file_path_parts)}"

                print(f"\nAttempting to read tree pack file: {pack_file_full_path}")

                with open(pack_file_full_path, 'rb') as pf:
                    pack_data = pf.read()

                print(f"Read {len(pack_data)} bytes from pack file.")

                offset = tree_blob_loc['offset']
                length = tree_blob_loc['length']

                if offset + length > len(pack_data):
                    raise ValueError(f"Offset ({offset}) + Length ({length}) exceeds pack file size ({len(pack_data)}).")

                compressed_tree_data_from_pack = pack_data[offset : offset + length]
                print(f"Extracted {len(compressed_tree_data_from_pack)} bytes of compressed tree data from pack file (offset: {offset}, length: {length}).")

                # This extracted chunk is an LZ4 compressed block, likely with the 4-byte prefix
                decompressed_tree_data_bytes = decompress_lz4_data(compressed_tree_data_from_pack)
                print(f"\nSuccessfully decompressed tree data (length: {len(decompressed_tree_data_bytes)} bytes).")
                # print(decompressed_tree_data_bytes[:200]) # Print first 200 bytes as it's binary

                # This variable will hold the parsed tree if successful
                parsed_tree_object = None
                backup_set_uuid = parsed_json.get("backupPlanUUID") # Assuming backupPlanUUID is the set UUID

                try:
                    parsed_tree_object = parse_tree_data(decompressed_tree_data_bytes)
                    print("\nSuccessfully Parsed Root Tree Data:")
                    # print(json.dumps(parsed_tree_object, indent=2, default=lambda o: o.__dict__ if hasattr(o, '__dict__') else str(o)))

                    # --- Attempt to find and restore a file ---
                    file_to_restore_node = None
                    file_to_restore_name = None

                    # Look for a file in the root tree first (e.g. "file 1.txt")
                    # However, we know "file 1.txt" has problematic BlobLoc.
                    # So, let's look for a subdirectory and a file within it.

                    for child_name, child_node in parsed_tree_object.childNodes.items():
                        print(f"Root Child: {child_name}, isTree: {child_node.isTree}")
                        if child_node.isTree and child_node.treeBlobLoc:
                            print(f"  Found subdirectory: {child_name}")
                            print(f"  Subdirectory treeBlobLoc: {child_node.treeBlobLoc}")

                            sub_tree_data_bytes = get_and_decompress_blob_from_loc(child_node.treeBlobLoc, storage_location_root, backup_set_uuid)
                            if sub_tree_data_bytes:
                                try:
                                    parsed_sub_tree = parse_tree_data(sub_tree_data_bytes)
                                    print(f"\nSuccessfully Parsed Sub-Tree Data for '{child_name}':")
                                    # print(json.dumps(parsed_sub_tree, indent=2, default=lambda o: o.__dict__ if hasattr(o, '__dict__') else str(o)))

                                    for sub_child_name, sub_child_node in parsed_sub_tree.childNodes.items():
                                        print(f"    Sub-Child: {sub_child_name}, isTree: {sub_child_node.isTree}")
                                        if not sub_child_node.isTree and sub_child_node.dataBlobLocs:
                                            # Found a file in the subdirectory
                                            # Let's try to restore the first one we find with a valid-looking BlobLoc
                                            # For this test, check if relativePath exists.
                                            if sub_child_node.dataBlobLocs[0].relativePath:
                                                file_to_restore_node = sub_child_node
                                                file_to_restore_name = f"{child_name.rstrip('/')}/{sub_child_name}" # Construct full-ish path
                                                print(f"      Selected file for restoration test: {file_to_restore_name}")
                                                break # Found a file to try
                                    if file_to_restore_node:
                                        break # Move to restoration attempt
                                except Exception as sub_tree_parse_error:
                                    print(f"\nError parsing binary sub-tree data for '{child_name}': {sub_tree_parse_error}")
                            else:
                                print(f"  Could not retrieve/decompress sub-tree data for {child_name}")

                        if file_to_restore_node: # If found in a subdirectory
                            break

                    # If no suitable file in subdirectories, reluctantly consider "file 1.txt" if needed for testing structure,
                    # but knowing its BlobLoc is problematic. For now, focus on subdirectories.

                    if file_to_restore_node and file_to_restore_name:
                        print(f"\n--- Attempting to restore file: {file_to_restore_name} ---")
                        if not file_to_restore_node.dataBlobLocs:
                            print("  Error: File node has no dataBlobLocs.")
                        else:
                            # Assuming single blob for simplicity first. Arq can split files.
                            # The Node.dataBlobLocs is a list, should concatenate them all.
                            all_file_bytes = bytearray()
                            for idx, blob_loc in enumerate(file_to_restore_node.dataBlobLocs):
                                print(f"  Processing dataBlobLoc {idx} for {file_to_restore_name}: {blob_loc}")
                                if not blob_loc.isPacked: # For now, only handle packed blobs from blobpacks
                                    print(f"    Skipping dataBlobLoc {idx} as it's not marked as packed or relativePath is missing/problematic.")
                                    # This check also implicitly handles the case of file1.txt's problematic BlobLoc
                                    # because get_and_decompress_blob_from_loc checks for relativePath.
                                    # However, file1.txt's relativePath IS null, so it would be skipped by get_and_decompress_blob_from_loc.
                                    # If a blob is NOT packed, it might be a direct reference (e.g. Arq5 style 'objects')
                                    # which this get_and_decompress_blob_from_loc doesn't handle yet.
                                    # For this test, we are looking for blobs in blobpacks.
                                    continue

                                chunk_bytes = get_and_decompress_blob_from_loc(blob_loc, storage_location_root, backup_set_uuid)
                                if chunk_bytes:
                                    all_file_bytes.extend(chunk_bytes)
                                else:
                                    print(f"    Error: Could not get/decompress data chunk {idx} for {file_to_restore_name}. Restoration failed.")
                                    all_file_bytes = None # Mark as failed
                                    break

                            if all_file_bytes is not None:
                                restored_file_path = f"./{file_to_restore_name.replace('/', '_')}_restored.dat"
                                with open(restored_file_path, 'wb') as rf:
                                    rf.write(all_file_bytes)
                                print(f"\nSuccessfully restored '{file_to_restore_name}' to '{restored_file_path}' ({len(all_file_bytes)} bytes)")
                    else:
                        print("\nNo suitable file found for restoration test in subdirectories.")

                except Exception as tree_parse_error:
                    print(f"\nError parsing binary root tree data: {tree_parse_error}")
                    print("Dumping first 200 bytes of decompressed tree data that failed to parse:")
                    print(decompressed_tree_data_bytes[:200])


            else: # 'node' or 'treeBlobLoc' not found
                print("\n'node' or 'treeBlobLoc' not found in the parsed backup record JSON.")
                tree_blob_loc = None # Ensure it's defined for the finally block or further checks

        except UnicodeDecodeError as ude: # Specifically for backup record JSON string decoding
            print(f"Could not decode decompressed backup record as UTF-8: {ude}")
            print("Printing raw decompressed backup record bytes (first 200):")
            print(decompressed_record_data[:200]) # This is decompressed_record_data, not tree data
        except json.JSONDecodeError as jde: # Specifically for backup record JSON parsing
            print(f"Could not parse decompressed backup record as JSON: {jde}")
            print("Printing decompressed backup record string (first 500 chars):")
            print(decompressed_record_data.decode('utf-8', errors='ignore')[:500]) # same here
        except lz4.block.LZ4BlockError as lz4e: # For LZ4 errors during backup record or tree data decompression
            # Need to know which decompression failed. The current structure makes this ambiguous.
            # For now, assume it could be either. If tree decompression fails, it's handled inside its own try-except.
            # This specific catch here is more for the backup record's decompression.
            print(f"LZ4 Decompression Error (likely for backup record or unhandled for tree pack): {lz4e}")

    except FileNotFoundError:
        print(f"Error: Backup record file not found at {backup_record_path}")
    except ValueError as ve: # General value errors (e.g., from struct unpack, data too short)
        print(f"ValueError: {ve}")
    # Removed the generic lz4.block.LZ4BlockError from here as it's too broad
    # and should be handled closer to where decompress_lz4_data is called if needed.
    except Exception as e: # Catch-all for other unexpected errors during main execution flow
        print(f"An unexpected error occurred in main: {e}")
        import traceback
        traceback.print_exc()

def get_and_decompress_blob_from_loc(blob_loc: BlobLoc, storage_location_root: str, backup_set_uuid: str) -> Optional[bytes]:
    """
    Reads data from a pack file as specified by a BlobLoc and decompresses it.
    Assumes LZ4 compression with 4-byte prefix for the packed blob itself.
    Returns decompressed data as bytes, or None on error.
    """
    if not blob_loc or not blob_loc.isPacked or not blob_loc.relativePath:
        print(f"Error: BlobLoc is not suitable for packed extraction (isPacked={blob_loc.isPacked if blob_loc else 'N/A'}, relativePath={blob_loc.relativePath if blob_loc else 'N/A'})")
        return None

    # Construct full path to the pack file
    # relativePath starts with /<backup_set_uuid>/...
    # We need to strip the leading / and the backup_set_uuid part if storage_location_root already includes it,
    # or construct it carefully.
    # Example: /FD55.../treepacks/A4/...pack
    # Path parts after stripping leading /: ['FD55...', 'treepacks', 'A4', '...pack']
    # Our storage_location_root is "tests/arq_storage_location"
    # The backup_set_uuid is like "FD55..."
    # Full path: storage_location_root / backup_set_uuid / relativePath_components_after_uuid

    path_components = blob_loc.relativePath.strip('/').split('/')
    if not path_components or path_components[0] != backup_set_uuid:
        # This check might be too strict if relativePath sometimes doesn't include the UUID prefix
        # For now, assume it does, as seen in treeBlobLoc from backup record.
        # print(f"Warning: BlobLoc relativePath '{blob_loc.relativePath}' does not seem to start with backup_set_uuid '{backup_set_uuid}'")
        # Fallback: assume path_components are relative to storage_location_root/backup_set_uuid
        # This means path_components = ['treepacks', 'A4', '...'] if UUID was already stripped by data source
        # For now, let's assume the full path with UUID is always given in BlobLoc.relativePath for packed data.
        # So, path_components[0] is UUID, path_components[1:] is the rest.
        pack_file_sub_path = "/".join(path_components[1:])
    else:
        # First component is UUID, join the rest
        pack_file_sub_path = "/".join(path_components[1:])


    pack_file_full_path = f"{storage_location_root}/{backup_set_uuid}/{pack_file_sub_path}"

    print(f"  Attempting to read pack file for blob: {pack_file_full_path}")

    try:
        with open(pack_file_full_path, 'rb') as pf:
            pack_data = pf.read()
        print(f"  Read {len(pack_data)} bytes from pack file {pack_file_full_path}.")

        offset = blob_loc.offset
        length = blob_loc.length

        if offset + length > len(pack_data):
            print(f"  Error: Offset ({offset}) + Length ({length}) exceeds pack file size ({len(pack_data)}).")
            return None

        compressed_blob_data = pack_data[offset : offset + length]
        print(f"  Extracted {len(compressed_blob_data)} bytes of compressed blob data from pack (offset: {offset}, length: {length}).")

        if blob_loc.compressionType == 2: # LZ4
            # This packed item is itself an LZ4 block, likely with the 4-byte prefix
            decompressed_data = decompress_lz4_data(compressed_blob_data)
            print(f"  Successfully decompressed blob data (length: {len(decompressed_data)} bytes).")
            return decompressed_data
        elif blob_loc.compressionType == 0: # None
             print(f"  Blob data is not compressed (type 0). Length: {len(compressed_blob_data)}")
             return compressed_blob_data
        else:
            print(f"  Error: Unsupported compression type {blob_loc.compressionType} for blob.")
            return None

    except FileNotFoundError:
        print(f"  Error: Pack file not found at {pack_file_full_path}")
        return None
    except ValueError as e: # From decompress_lz4_data or other issues
        print(f"  ValueError during blob processing: {e}")
        return None
    except lz4.block.LZ4BlockError as e:
        print(f"  LZ4 Decompression Error for blob: {e}")
        return None
    except Exception as e:
        print(f"  An unexpected error occurred during blob processing: {e}")
        return None

if __name__ == "__main__":
    main()
