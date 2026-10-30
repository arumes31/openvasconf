package gmp

import (
	"context"
	"encoding/xml"
)

// EnsureTaskReportRetention changes only task preferences, keeping the task ID,
// schedule and scan configuration intact. The caller verifies task ownership.
func (c *Client) EnsureTaskReportRetention(ctx context.Context, taskID string) error {
	request := struct {
		XMLName xml.Name `xml:"get_tasks"`
		TaskID  string   `xml:"task_id,attr"`
		Details string   `xml:"details,attr"`
	}{TaskID: taskID, Details: "1"}
	var response taskListResponse
	if err := c.call(ctx, request, &response); err != nil {
		return err
	}
	if err := checkStatus("get_tasks", response.responseStatus); err != nil {
		return err
	}
	if len(response.Tasks) != 1 || response.Tasks[0].ID != taskID {
		return ErrNotFound
	}
	prefs := make(map[string]string)
	for _, pref := range response.Tasks[0].Preferences {
		prefs[pref.Name] = pref.Value
	}
	if prefs["auto_delete"] == "keep" && prefs["auto_delete_data"] == "3" {
		return nil
	}
	modify := struct {
		XMLName     xml.Name         `xml:"modify_task"`
		TaskID      string           `xml:"task_id,attr"`
		Preferences []taskPreference `xml:"preferences>preference"`
	}{TaskID: taskID, Preferences: reportRetentionPreferences()}
	return c.modify(ctx, "modify_task", modify)
}
