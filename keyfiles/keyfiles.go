package keyfiles

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/twmb/murmur3"
)

type FileMetadata struct {
	Name    string
	Size    int64
	ModTime time.Time
}

type FileMetadatas []FileMetadata

func (f FileMetadatas) Hash() ([]byte, error) {
	hash := murmur3.SeedNew128(1, 1)
	buf := bytes.NewBuffer(make([]byte, 0, len(f)*36))

	for i, m := range f {
		buf.Reset()

		if err := binary.Write(buf, binary.LittleEndian, uint64(0xdeadbeef)); err != nil {
			return nil, fmt.Errorf("write mark: %w", err)
		}

		if err := binary.Write(buf, binary.LittleEndian, uint64(i)); err != nil {
			return nil, fmt.Errorf("write index: %w", err)
		}

		if err := binary.Write(buf, binary.LittleEndian, m.Size); err != nil {
			return nil, fmt.Errorf("write size: %w", err)
		}

		if err := binary.Write(buf, binary.LittleEndian, m.ModTime.UnixMilli()); err != nil {
			return nil, fmt.Errorf("write modtime: %w", err)
		}

		if _, err := buf.WriteString(m.Name); err != nil {
			return nil, fmt.Errorf("write name: %w", err)
		}

		hash.Write(buf.Bytes())
	}

	return hash.Sum(nil), nil
}

// GetFileMetadata returns the metadata of all files in a directory
// it skips directories, hidden and ignored files
// if a symlink is encountered, the metadata of the target is returned
func GetFileMetadata(dir string) (FileMetadatas, map[string]string, error) {
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("read dir: %w", err)
	}

	files := make(FileMetadatas, 0, len(dirEntries))
	skipped := make(map[string]string)

	for _, e := range dirEntries {
		info, err := os.Stat(filepath.Join(dir, e.Name()))
		if err != nil {
			// return partial results
			return files, skipped, fmt.Errorf("stat: %w", err)
		}

		if skip, reason := skipFile(info); skip {
			skipped[e.Name()] = reason
			continue
		}

		files = append(files, FileMetadata{
			Name:    e.Name(),
			Size:    info.Size(),
			ModTime: info.ModTime(),
		})

	}

	return files, skipped, nil
}

func skipFile(fileInfo fs.FileInfo) (bool, string) {
	if fileInfo.IsDir() {
		return true, "directory"
	}

	if strings.HasPrefix(fileInfo.Name(), ".") {
		return true, "hidden file"
	}

	if strings.HasSuffix(fileInfo.Name(), ".ignore") {
		return true, "ignored file"
	}

	return false, ""
}
