package api

import "net/url"

// pathParam returns a raw path parameter. With UseRawPath enabled, percent
// sequences such as %2F stay encoded, so identifiers containing "/" survive
// inside a single parameter and are decoded here.
func pathParam(c interface{ Param(string) string }, name string) string {
	value := c.Param(name)
	if decoded, err := url.PathUnescape(value); err == nil {
		return decoded
	}
	return value
}
