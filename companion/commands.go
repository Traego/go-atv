package companion

import "fmt"

// Button is a key on the remote, sent as a HID command. Sleep and Wake are
// how the device is turned off and on.
type Button int64

// The buttons the device understands.
const (
	ButtonUp               Button = 1
	ButtonDown             Button = 2
	ButtonLeft             Button = 3
	ButtonRight            Button = 4
	ButtonMenu             Button = 5
	ButtonSelect           Button = 6
	ButtonHome             Button = 7
	ButtonVolumeUp         Button = 8
	ButtonVolumeDown       Button = 9
	ButtonSiri             Button = 10
	ButtonScreensaver      Button = 11
	ButtonSleep            Button = 12
	ButtonWake             Button = 13
	ButtonPlayPause        Button = 14
	ButtonChannelIncrement Button = 15
	ButtonChannelDecrement Button = 16
	ButtonGuide            Button = 17
	ButtonPageUp           Button = 18
	// ButtonPageDown opens Control Center.
	ButtonPageDown Button = 19
)

var buttonNames = map[Button]string{
	ButtonUp: "up", ButtonDown: "down", ButtonLeft: "left", ButtonRight: "right",
	ButtonMenu: "menu", ButtonSelect: "select", ButtonHome: "home",
	ButtonVolumeUp: "volume_up", ButtonVolumeDown: "volume_down", ButtonSiri: "siri",
	ButtonScreensaver: "screensaver", ButtonSleep: "sleep", ButtonWake: "wake",
	ButtonPlayPause: "play_pause", ButtonChannelIncrement: "channel_up",
	ButtonChannelDecrement: "channel_down", ButtonGuide: "guide",
	ButtonPageUp: "page_up", ButtonPageDown: "control_center",
}

func (b Button) String() string {
	if n, ok := buttonNames[b]; ok {
		return n
	}
	return fmt.Sprintf("Button(%d)", int64(b))
}

// ParseButton returns the button with the given name, as String prints it.
func ParseButton(name string) (Button, bool) {
	for b, n := range buttonNames {
		if n == name {
			return b, true
		}
	}
	return 0, false
}

// MediaControlCommand is a playback command, sent as _mcc.
type MediaControlCommand int64

// The media control commands.
const (
	MediaPlay               MediaControlCommand = 1
	MediaPause              MediaControlCommand = 2
	MediaNextTrack          MediaControlCommand = 3
	MediaPreviousTrack      MediaControlCommand = 4
	MediaGetVolume          MediaControlCommand = 5
	MediaSetVolume          MediaControlCommand = 6
	MediaSkipBy             MediaControlCommand = 7
	MediaFastForwardBegin   MediaControlCommand = 8
	MediaFastForwardEnd     MediaControlCommand = 9
	MediaRewindBegin        MediaControlCommand = 10
	MediaRewindEnd          MediaControlCommand = 11
	MediaGetCaptionSettings MediaControlCommand = 12
	MediaSetCaptionSettings MediaControlCommand = 13
)

// MediaControlFlags says which playback controls apply right now. The device
// sends them in the _iMC event.
type MediaControlFlags int64

// The media control flags.
const (
	MediaControlPlay          MediaControlFlags = 0x0001
	MediaControlPause         MediaControlFlags = 0x0002
	MediaControlNextTrack     MediaControlFlags = 0x0004
	MediaControlPreviousTrack MediaControlFlags = 0x0008
	MediaControlFastForward   MediaControlFlags = 0x0010
	MediaControlRewind        MediaControlFlags = 0x0020
	MediaControlVolume        MediaControlFlags = 0x0100
	MediaControlSkipForward   MediaControlFlags = 0x0200
	MediaControlSkipBackward  MediaControlFlags = 0x0400
)

// SystemStatus is the device's attention state, which is as close as the
// protocol gets to a power state. Asleep is off; the rest are on.
type SystemStatus int64

// The system states. Idle has not been seen for certain.
const (
	StatusUnknown     SystemStatus = 0
	StatusAsleep      SystemStatus = 1
	StatusScreensaver SystemStatus = 2
	StatusAwake       SystemStatus = 3
	StatusIdle        SystemStatus = 4
)

func (s SystemStatus) String() string {
	switch s {
	case StatusAsleep:
		return "asleep"
	case StatusScreensaver:
		return "screensaver"
	case StatusAwake:
		return "awake"
	case StatusIdle:
		return "idle"
	}
	return "unknown"
}

// On reports whether the status means the device is awake in some form.
func (s SystemStatus) On() bool {
	return s == StatusScreensaver || s == StatusAwake || s == StatusIdle
}

// TouchAction is the phase of a touchpad event.
type TouchAction int64

// The touch phases.
const (
	TouchPress   TouchAction = 1
	TouchHold    TouchAction = 3
	TouchRelease TouchAction = 4
	TouchClick   TouchAction = 5
)

// Event names the device sends, for Subscribe and Handle.
const (
	// EventMediaControls is _iMC: the MediaControlFlags changed. The device
	// sends it on connect.
	EventMediaControls = "_iMC"
	// EventSystemStatus carries a "state" of SystemStatus.
	EventSystemStatus = "SystemStatus"
	// EventTVSystemStatus is the same on newer tvOS versions.
	EventTVSystemStatus = "TVSystemStatus"
)

// ErrorNoHandler is the CommandError code for a request the device does not
// handle. Newer tvOS versions answer FetchAttentionState with it.
const ErrorNoHandler int64 = 58822
