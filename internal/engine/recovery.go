package engine

import (
	"log"
	"runtime/debug"
)

// SafeGo runs a function in a goroutine with panic recovery
func SafeGo(fn func(), name string) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[PANIC] Module '%s' panicked: %v", name, r)
				log.Printf("[PANIC] Stack trace:\n%s", string(debug.Stack()))
				// Continue running — don't crash the proxy
			}
		}()
		fn()
	}()
}
