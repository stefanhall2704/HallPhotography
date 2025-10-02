package services

import (
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/stefanhall2704/GoPhotography/model"
)

const MinimumBookingNoticeDays = 14 // 2 weeks

// Utility function to get keys from a map
func Keys(m map[uint]bool) []uint {
	result := make([]uint, 0, len(m))
	for k := range m {
		result = append(result, k)
	}
	return result
}

// Parse slot duration from string format like "30min"
func ParseSlotDuration(durationStr string) (time.Duration, error) {
	if strings.HasSuffix(durationStr, "min") {
		minStr := strings.TrimSuffix(durationStr, "min")
		minutes, err := time.ParseDuration(minStr + "m")
		if err != nil {
			return 0, fmt.Errorf("invalid duration: %w", err)
		}
		return minutes, nil
	}
	return 0, fmt.Errorf("unsupported duration format: %s", durationStr)
}

// Get available time slots for minis sessions
func GetAvailableTimeSlots(db *gorm.DB, minisID uint, startStr, endStr, durationStr string) ([]string, error) {
	// Parse times
	start, err := time.Parse(time.RFC3339, startStr)
	if err != nil {
		return nil, fmt.Errorf("invalid start time: %w", err)
	}
	end, err := time.Parse(time.RFC3339, endStr)
	if err != nil {
		return nil, fmt.Errorf("invalid end time: %w", err)
	}

	// Parse duration
	slotDuration, err := ParseSlotDuration(durationStr)
	if err != nil {
		return nil, err
	}

	// Get all booked slots for this minis session
	var booked []model.BookMinis
	if err := db.Where("minis_id = ?", minisID).Find(&booked).Error; err != nil {
		return nil, err
	}

	// Build a set of booked strings like "03:00 PM"
	bookedSet := make(map[string]struct{})
	for _, b := range booked {
		bookedSet[b.TimeSlot] = struct{}{}
	}

	// Build available slots
	var available []string
	for t := start; t.Add(slotDuration).Equal(end) || t.Add(slotDuration).Before(end); t = t.Add(slotDuration) {
		display := t.Format("03:04 PM")
		if _, taken := bookedSet[display]; !taken {
			available = append(available, display)
		}
	}

	return available, nil
}

// Get available time slots for normal sessions
func GetAvailableSessionTimeSlots(db *gorm.DB, sessionID uint, startStr, endStr, durationStr string) ([]string, error) {
	// Parse times
	start, err := time.Parse(time.RFC3339, startStr)
	if err != nil {
		return nil, fmt.Errorf("invalid start time: %w", err)
	}
	end, err := time.Parse(time.RFC3339, endStr)
	if err != nil {
		return nil, fmt.Errorf("invalid end time: %w", err)
	}

	// Parse duration
	slotDuration, err := ParseSlotDuration(durationStr)
	if err != nil {
		return nil, err
	}

	// Get all booked slots for this session
	var booked []model.BookSession
	if err := db.Where("session_id = ?", sessionID).Find(&booked).Error; err != nil {
		return nil, err
	}

	// Build a set of booked strings like "03:00 PM"
	bookedSet := make(map[string]struct{})
	for _, b := range booked {
		bookedSet[b.TimeSlot] = struct{}{}
	}

	// Build available slots
	var available []string
	for t := start; t.Add(slotDuration).Equal(end) || t.Add(slotDuration).Before(end); t = t.Add(slotDuration) {
		display := t.Format("03:04 PM")
		if _, taken := bookedSet[display]; !taken {
			available = append(available, display)
		}
	}

	return available, nil
}

// Check if a timeslot is available for minis sessions
func CheckIfMinisTimeslotIsAvailable(db *gorm.DB, timeSlot string, minisSessionId uint) (bool, error) {
	var exists bool
	err := db.Model(&model.BookMinis{}).
		Select("count(*) > 0").
		Where("time_slot = ? AND minis_id = ?", timeSlot, minisSessionId).
		Find(&exists).Error

	if err != nil {
		return false, err
	}
	return !exists, nil
}

// Check if a timeslot is available for normal sessions
func CheckIfSessionTimeslotIsAvailable(db *gorm.DB, timeSlot string, sessionId uint) (bool, error) {
	var exists bool
	err := db.Model(&model.BookSession{}).
		Select("count(*) > 0").
		Where("time_slot = ? AND session_id = ?", timeSlot, sessionId).
		Find(&exists).Error

	if err != nil {
		return false, err
	}
	return !exists, nil
}

// ValidateBookingDate checks if a booking date is at least MinimumBookingNoticeDays in the future
func ValidateBookingDate(bookingDate time.Time) error {
	now := time.Now()
	minimumDate := now.AddDate(0, 0, MinimumBookingNoticeDays)
	
	if bookingDate.Before(minimumDate) {
		return fmt.Errorf("bookings must be made at least %d days in advance", MinimumBookingNoticeDays)
	}
	
	return nil
}

// GetMinisSessionDate retrieves the date for a specific minis session and day
func GetMinisSessionDate(db *gorm.DB, minisID uint) (time.Time, error) {
	var minisDay model.MinisDay
	
	if err := db.Where("minis_id = ?", minisID).First(&minisDay).Error; err != nil {
		return time.Time{}, fmt.Errorf("failed to find minis session date: %w", err)
	}
	
	return minisDay.Start, nil
}

// GetSessionDate retrieves the date for a specific session
func GetSessionDate(db *gorm.DB, sessionID uint) (time.Time, error) {
	var sessionDay model.SessionDay
	
	if err := db.Where("session_id = ?", sessionID).First(&sessionDay).Error; err != nil {
		return time.Time{}, fmt.Errorf("failed to find session date: %w", err)
	}
	
	return sessionDay.Start, nil
}
