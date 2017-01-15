package hrproxy

import (
	"io/ioutil"
	"time"
	"os"
)

type FileBinaryCache struct {
	path  string
	data  []byte
	mtime time.Time
}

func NewFileBinaryCache(path string) (*FileBinaryCache, error) {
	fbc := &FileBinaryCache{
		path: path,
	}
	if !fbc.IsEmpty() {
		if _, err := fbc.Fetch(); err != nil {
			return nil, err
		}
	}
	return fbc, nil
}

func (fbc *FileBinaryCache) IsEmpty() bool {
	if fbc.data != nil {
		return false
	}
	_, err := os.Stat(fbc.path)
	return err != nil
}

func (fbc *FileBinaryCache) Get() ([]byte, error) {
	if fbc.data != nil {
		return fbc.data, nil
	}
	return fbc.Fetch()
}

func (fbc *FileBinaryCache) Put(data []byte) error {
	fbc.data = data[:]
	if err := fbc.Flush(); err != nil {
		return err
	}
	fbc.mtime = time.Now()
	return nil
}

func (fbc *FileBinaryCache) Fetch() ([]byte,  error) {
	var err error
	fbc.data, err = ioutil.ReadFile(fbc.path)
	return fbc.data, err
}

func (fbc *FileBinaryCache) Flush() error {
	return ioutil.WriteFile(fbc.path, fbc.data, 600)
}
