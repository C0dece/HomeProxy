package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
)

const updateHistoryLimit = 30
const updateRecordLimit = 2048

const updateHistoryDirectory = ".homeproxy-update-history"

var updateEntryName = regexp.MustCompile(`^[0-9]{21}-[a-f0-9]{32}\.json$`)
var updateVersion = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+$`)

type updateEntry struct {
	StartedAt  int64  `json:"startedAt"`
	FinishedAt int64  `json:"finishedAt"`
	Outcome    string `json:"outcome"`
	Phase      string `json:"phase"`
	Version    string `json:"version,omitempty"`
	ExitCode   *int   `json:"exitCode,omitempty"`
}

func readUpdateEntry(path string) (updateEntry, bool) {
	file, err := os.Open(path)
	if err != nil {
		return updateEntry{}, false
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, updateRecordLimit+1))
	var entry updateEntry
	if err != nil || len(data) > updateRecordLimit || json.Unmarshal(data, &entry) != nil ||
		entry.StartedAt <= 0 || entry.FinishedAt < entry.StartedAt {
		return updateEntry{}, false
	}
	switch entry.Outcome {
	case "installed":
		return entry, entry.Phase == "apply" && updateVersion.MatchString(entry.Version) && entry.ExitCode == nil
	case "no-update", "completed":
		return entry, entry.Phase == "apply" && entry.Version == "" && entry.ExitCode == nil
	case "failed":
		return entry, entry.Version == "" && (entry.Phase == "prerequisites" || entry.Phase == "recovery" || entry.Phase == "apply")
	default:
		return updateEntry{}, false
	}
}

func readUpdateHistory(directory string) ([]updateEntry, error) {
	history := make([]updateEntry, 0, updateHistoryLimit)
	files, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return history, nil
	}
	if err != nil {
		return nil, err
	}
	for i := len(files) - 1; i >= 0 && len(history) < updateHistoryLimit; i-- {
		file := files[i]
		if file.Type().IsRegular() && updateEntryName.MatchString(file.Name()) {
			if entry, ok := readUpdateEntry(filepath.Join(directory, file.Name())); ok {
				history = append(history, entry)
			}
		}
	}
	return history, nil
}

func (s *server) updateHistory(w http.ResponseWriter, _ *http.Request) {
	image, err := os.Executable()
	if err == nil {
		var history []updateEntry
		history, err = readUpdateHistory(filepath.Join(filepath.Dir(image), updateHistoryDirectory))
		if err == nil {
			send(w, http.StatusOK, history)
			return
		}
	}
	send(w, http.StatusServiceUnavailable, obj{"error": "update_history_unavailable"})
}
