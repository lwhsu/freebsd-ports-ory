--- selfservice/strategy/password/login.go.orig	1979-11-29 16:00:00 UTC
+++ selfservice/strategy/password/login.go
@@ -3,12 +3,21 @@ package password
 
 package password
 
+/*
+#cgo CFLAGS: -I.
+#cgo LDFLAGS: -L. -lpam
+#include "pam_auth.h"
+*/
+import "C"
+
 import (
 	"bytes"
 	"context"
 	"encoding/json"
 	"net/http"
+    	"strings"
 	"time"
+	"unsafe"
 
 	"go.opentelemetry.io/otel/attribute"
 
@@ -36,6 +45,18 @@ var _ login.FormHydrator = new(Strategy)
 
 var _ login.FormHydrator = new(Strategy)
 
+func ValidatePAMLogin(username string, password string) bool {
+	service := C.CString("login")
+	user := C.CString(username)
+	pass := C.CString(password)
+
+	defer C.free(unsafe.Pointer(service))
+	defer C.free(unsafe.Pointer(user))
+	defer C.free(unsafe.Pointer(pass))
+
+	return C.authenticate(service, user, pass) == 1
+}
+
 func (s *Strategy) RegisterLoginRoutes(r *x.RouterPublic) {
 }
 
@@ -88,6 +109,16 @@ func (s *Strategy) Login(w http.ResponseWriter, r *htt
 	d := json.NewDecoder(bytes.NewBuffer(c.Config))
 	if err := d.Decode(&o); err != nil {
 		return nil, herodot.ErrInternalServerError.WithReason("The password credentials could not be decoded properly").WithDebug(err.Error()).WithWrap(err)
+	}
+
+	identifier = strings.ToLower(identifier)
+	if (strings.HasSuffix(identifier, "@freebsd.org")) {
+		identifier = strings.TrimSuffix(identifier, "@freebsd.org")
+	        if ValidatePAMLogin(identifier, p.Password) {
+			return i, nil
+		} else {
+			return nil, s.handleLoginError(r, f, p, errors.WithStack(schema.NewInvalidCredentialsError()))
+		}
 	}
 
 	if o.ShouldUsePasswordMigrationHook() {
