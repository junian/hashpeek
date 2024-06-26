# HashPeek

Console .NET Core app to scan all files in a specific folder
- [x] Accept folder path as an argument
- [x] Enumerate files in folder and subfolders
- [x] Calculate md5,sha1,sha256 hashes for each file
- [x] Print to console the number of files scanned and the total time
- [x] Compile app for Windows and macOS platform



Optional features
- [x] Save information about file into SQLite database (table hashes: md5,sha1,sha256,file_size,last_seen) with no duplicates
- [x] Increment column 'scanned' and update 'last_seen' in table 'hashes' if the file was previously scanned (key is sha256 hash)
- [x] Add caching and do not scan file_path which was previously scanned
- [x] Log errors in a separate file



Example of usage:   
- Windows: `hashpeek C:\Program Files (x86)`
- Linux: `hashpeek ~/Documents`
