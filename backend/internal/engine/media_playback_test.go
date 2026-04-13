package engine

import "testing"

func TestDetectPlaybackProfile(t *testing.T) {
	t.Parallel()

	cases := []struct {
		path        string
		wantExt     string
		wantFormat  string
		wantContent string
	}{
		{path: "sample.h264", wantExt: ".mp4", wantFormat: "h264", wantContent: "video/mp4"},
		{path: "sample.h265", wantExt: ".mp4", wantFormat: "hevc", wantContent: "video/mp4"},
		{path: "sample.ulaw", wantExt: ".m4a", wantFormat: "mulaw", wantContent: "audio/mp4"},
		{path: "sample.alaw", wantExt: ".m4a", wantFormat: "alaw", wantContent: "audio/mp4"},
		{path: "sample.g722", wantExt: ".m4a", wantFormat: "g722", wantContent: "audio/mp4"},
		{path: "sample.l16", wantExt: ".m4a", wantFormat: "s16be", wantContent: "audio/mp4"},
		{path: "sample.aac", wantExt: ".m4a", wantFormat: "aac", wantContent: "audio/mp4"},
		{path: "sample.opus", wantExt: ".m4a", wantFormat: "opus", wantContent: "audio/mp4"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()
			profile, err := detectPlaybackProfile(tc.path)
			if err != nil {
				t.Fatalf("detectPlaybackProfile(%q) error = %v", tc.path, err)
			}
			if profile.outputExt != tc.wantExt || profile.inputFormat != tc.wantFormat || profile.contentType != tc.wantContent {
				t.Fatalf("detectPlaybackProfile(%q) = %+v, want ext=%q format=%q content=%q", tc.path, profile, tc.wantExt, tc.wantFormat, tc.wantContent)
			}
		})
	}
}

