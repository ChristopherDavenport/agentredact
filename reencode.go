package agentredact

import (
	"bytes"
	"errors"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"
)

// errNoCodec is reencode's answer for an image format the standard
// library does not decode.
var errNoCodec = errors.New("agentredact: no decoder for the image's format")

// errTooManyPixels is reencode's answer for an image with more pixels
// than it is allowed to decode.
var errTooManyPixels = errors.New("agentredact: the image has too many pixels")

// reencode decodes data, an image whose bytes start as PNG, JPEG or
// GIF, and encodes its pixels again in the same format, returning the
// bytes and their media type. What is not pixels does not survive:
// PNG's text and other ancillary chunks, JPEG's EXIF, comments and
// thumbnails, a GIF's comment and application extensions and every
// frame after the first, and any bytes after the image's end. Only the
// header is read before maxPixels is checked, so a small file naming a
// huge image is refused before it is decoded. The encoders are the
// standard library's and deterministic: the same bytes in give the
// same bytes out. A format it does not decode is errNoCodec, and bytes
// that do not decode are the decoder's error.
func reencode(data []byte, maxPixels int64) ([]byte, string, error) {
	type codec struct {
		mediaType string
		config    func([]byte) (image.Config, error)
		decode    func([]byte) (image.Image, error)
		encode    func(*bytes.Buffer, image.Image) error
	}
	var c codec
	switch {
	case bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n")):
		c = codec{"image/png",
			func(b []byte) (image.Config, error) { return png.DecodeConfig(bytes.NewReader(b)) },
			func(b []byte) (image.Image, error) { return png.Decode(bytes.NewReader(b)) },
			func(w *bytes.Buffer, m image.Image) error { return png.Encode(w, m) }}
	case bytes.HasPrefix(data, []byte("\xff\xd8\xff")):
		c = codec{"image/jpeg",
			func(b []byte) (image.Config, error) { return jpeg.DecodeConfig(bytes.NewReader(b)) },
			func(b []byte) (image.Image, error) { return jpeg.Decode(bytes.NewReader(b)) },
			func(w *bytes.Buffer, m image.Image) error { return jpeg.Encode(w, m, &jpeg.Options{Quality: 90}) }}
	case bytes.HasPrefix(data, []byte("GIF87a")), bytes.HasPrefix(data, []byte("GIF89a")):
		c = codec{"image/gif",
			func(b []byte) (image.Config, error) { return gif.DecodeConfig(bytes.NewReader(b)) },
			func(b []byte) (image.Image, error) { return gif.Decode(bytes.NewReader(b)) },
			func(w *bytes.Buffer, m image.Image) error { return gif.Encode(w, m, nil) }}
	default:
		return nil, "", errNoCodec
	}
	cfg, err := c.config(data)
	if err != nil {
		return nil, "", err
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || int64(cfg.Width)*int64(cfg.Height) > maxPixels {
		return nil, "", errTooManyPixels
	}
	m, err := c.decode(data)
	if err != nil {
		return nil, "", err
	}
	var out bytes.Buffer
	if err := c.encode(&out, m); err != nil {
		return nil, "", err
	}
	return out.Bytes(), c.mediaType, nil
}
