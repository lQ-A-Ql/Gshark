//go:build !production

package miscpkg

import "os"

func allowUnsignedMISC() bool {
	return os.Getenv("MEOW_TRAFFIC_ALLOW_UNSIGNED_MISC") == "1"
}
