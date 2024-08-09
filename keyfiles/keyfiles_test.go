package keyfiles

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestGetFileMetadata(t *testing.T) {
	type args struct {
		dir string
	}

	// using to generate predictable mod times for files
	testTime := time.Now().Truncate(time.Second)

	tests := []struct {
		name     string
		argsFunc func(string) (*args, error) // sets up the temporary dir for the test
		want     FileMetadatas
		want1    map[string]string
		wantErr  bool
	}{
		{
			name: "non-existent dir",
			argsFunc: func(string) (*args, error) {
				return &args{os.TempDir() + "/TestGetFileMetadata-baddir-not-exist-1023727892"}, nil
			},
			wantErr: true,
		},
		{
			name: "empty dir",
			argsFunc: func(name string) (*args, error) {
				dir, err := mkTmpDir(t.Name(), name)
				if err != nil {
					return nil, err
				}

				return &args{dir}, nil
			},
			want:  FileMetadatas{},
			want1: map[string]string{},
		},
		{
			name: "all files skipped",
			argsFunc: func(name string) (*args, error) {
				dir, err := mkTmpDir(t.Name(), name)
				if err != nil {
					return nil, fmt.Errorf("mkTmpDir: %w", err)
				}

				if err := os.Mkdir(dir+"/ignored-dir", 0); err != nil {
					return nil, fmt.Errorf("os.Mkdir: %w", err)
				}

				files := map[string]createFile{
					".hidden-file": {},
					"file.ignore":  {},
				}

				if err := createFiles(dir, files); err != nil {
					return nil, err
				}

				return &args{dir}, nil
			},
			want: FileMetadatas{},
			want1: map[string]string{
				"ignored-dir":  "directory",
				".hidden-file": "hidden file",
				"file.ignore":  "ignored file",
			},
		},
		{
			name: "ignored and good files",
			argsFunc: func(name string) (*args, error) {
				dir, err := mkTmpDir(t.Name(), name)
				if err != nil {
					return nil, fmt.Errorf("mkTmpDir: %w", err)
				}

				if err := os.Mkdir(dir+"/ignored-dir", 0); err != nil {
					return nil, fmt.Errorf("os.Mkdir: %w", err)
				}

				files := map[string]createFile{
					".hidden-file": {},
					"file.ignore":  {},
					"key1":         {"key1 data", testTime.Add(1 * time.Second)},
					"key2":         {"key2 data2", testTime.Add(2 * time.Second)},
				}

				if err := createFiles(dir, files); err != nil {
					return nil, err
				}

				return &args{dir}, nil
			},
			want: FileMetadatas{
				FileMetadata{"key1", 9, testTime.Add(1 * time.Second)},
				FileMetadata{"key2", 10, testTime.Add(2 * time.Second)},
			},
			want1: map[string]string{
				"ignored-dir":  "directory",
				".hidden-file": "hidden file",
				"file.ignore":  "ignored file",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args, err := tt.argsFunc(tt.name)
			if err != nil {
				t.Fatal("failed to setup the test:", err)
			}

			// do not clean up failed tests
			doCleanup := true

			t.Cleanup(func() {
				if !doCleanup {
					t.Logf("skipping cleanup of '%s'", args.dir)
					return
				}

				dirToClean := args.dir

				// making sure we dont clean up some other path!
				if err := checkTmpDir(dirToClean); err != nil {
					t.Fatal("refusing to clean bad path:", err)
					return
				}

				if err := os.RemoveAll(dirToClean); err != nil {
					t.Fatal("failed to cleanup the test dir:", err)
				}

				t.Logf("cleaned up the test path at '%s'", dirToClean)
			})

			got, got1, err := GetFileMetadata(args.dir)
			if (err != nil) != tt.wantErr {
				doCleanup = false
				t.Errorf("GetFileMetadata() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !reflect.DeepEqual(got, tt.want) {
				doCleanup = false
				t.Errorf("GetFileMetadata() got = %#v, want %#v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				doCleanup = false
				t.Errorf("GetFileMetadata() got1 = %#v, want %#v", got1, tt.want1)
			}
		})
	}
}

type createFile struct {
	data  string
	mtime time.Time
}

func createFiles(dir string, files map[string]createFile) error {
	for fn, cfd := range files {
		fpath := dir + "/" + fn

		f, err := os.Create(fpath)
		if err != nil {
			return fmt.Errorf("os.Create '%s': %w", fpath, err)
		}

		if _, err := f.WriteString(cfd.data); err != nil {
			return fmt.Errorf("f.Write '%s': %w", fpath, err)
		}

		f.Close()

		if !cfd.mtime.IsZero() {
			if err := os.Chtimes(fpath, time.Time{}, cfd.mtime); err != nil {
				return fmt.Errorf("os.Chtimes '%s': %w", fpath, err)
			}
		}
	}

	return nil
}

func mkTmpDir(testname, name string) (string, error) {
	tmp := os.TempDir()

	if err := checkTmpDir(tmp); err != nil {
		return "", fmt.Errorf("bad tmp dir: %w", err)
	}

	d, err := os.MkdirTemp(tmp, testname+"-"+name+"-")
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir in %s (override with TMPDIR env var): %w", tmp, err)
	}

	// WARNING: do not delete the following lines!
	// making sure the returned directory is empty, to prevent cleaning up an existing directory.
	e, err := os.ReadDir(d)
	if err != nil {
		panic(err)
	}

	if len(e) > 0 {
		return "", errors.New("the created temp dir is not empty")
	}

	return d, nil
}

func checkTmpDir(path string) error {
	if len(path) == 0 {
		return fmt.Errorf("path '%s' is empty", path)
	}

	// relative paths are disallowed because `go test` uses TMPDIR variable too
	// also `go test` changes to the directory with the tests, so using relative paths can create confusion.
	if !filepath.IsAbs(path) {
		return fmt.Errorf("path '%s' is not absolute", path)
	}

	tmp := os.TempDir()

	if !strings.HasPrefix(path, tmp) {
		return fmt.Errorf("path '%s' is not in the TMPDIR", path)
	}

	return nil
}
