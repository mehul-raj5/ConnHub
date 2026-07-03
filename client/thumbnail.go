package main

import (
	"bytes"
	common "common"
	"fmt"
	"image"
	"image/jpeg"
	_ "image/gif"  // register GIF decoder
	_ "image/png"  // register PNG decoder
	"strings"
)

// Thumbnail geometry. Two source pixels map to one terminal cell vertically
// (the ▀ half-block trick), so thumbHeight rows render as thumbHeight/2 lines.
const (
	thumbMaxW = 30
	thumbMaxH = 30
)

// makeThumbnail returns a small JPEG preview for image files, or nil for
// non-images / on failure. Uses only the standard library (nearest-neighbor
// downscale) so no image-resize dependency is required.
func makeThumbnail(fileType string, data []byte) []byte {
	if !strings.HasPrefix(fileType, "image/") {
		return nil
	}
	src, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil
	}

	b := src.Bounds()
	tw, th := scaleToFit(b.Dx(), b.Dy(), thumbMaxW, thumbMaxH)
	small := resizeNearest(src, tw, th)

	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, small, &jpeg.Options{Quality: 60}); err != nil {
		return nil
	}
	return buf.Bytes()
}

// renderThumbnail decodes a thumbnail JPEG and returns inline terminal art using
// unicode upper-half-blocks (▀): the top pixel colors the glyph foreground, the
// bottom pixel colors its background, giving two vertical pixels per cell.
func renderThumbnail(thumb []byte) string {
	if len(thumb) == 0 {
		return ""
	}
	img, err := jpeg.Decode(bytes.NewReader(thumb))
	if err != nil {
		return ""
	}

	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	var sb strings.Builder
	for y := 0; y < h; y += 2 {
		for x := 0; x < w; x++ {
			tr, tg, tb := rgbAt(img, b.Min.X+x, b.Min.Y+y)
			br, bg, bb := tr, tg, tb
			if y+1 < h {
				br, bg, bb = rgbAt(img, b.Min.X+x, b.Min.Y+y+1)
			}
			fmt.Fprintf(&sb, "\x1b[38;2;%d;%d;%dm\x1b[48;2;%d;%d;%dm▀", tr, tg, tb, br, bg, bb)
		}
		sb.WriteString("\x1b[0m")
		if y+2 < h {
			sb.WriteByte('\n')
		}
	}
	return sb.String()
}

func rgbAt(img image.Image, x, y int) (uint8, uint8, uint8) {
	r, g, b, _ := img.At(x, y).RGBA()
	return uint8(r >> 8), uint8(g >> 8), uint8(b >> 8)
}

// scaleToFit returns the largest w×h (preserving aspect ratio) that fits within
// maxW×maxH; never upscales.
func scaleToFit(w, h, maxW, maxH int) (int, int) {
	if w <= 0 || h <= 0 {
		return 1, 1
	}
	if w <= maxW && h <= maxH {
		return w, h
	}
	tw := maxW
	th := h * maxW / w
	if th > maxH {
		th = maxH
		tw = w * maxH / h
	}
	if tw < 1 {
		tw = 1
	}
	if th < 1 {
		th = 1
	}
	return tw, th
}

// resizeNearest downscales src to tw×th using nearest-neighbor sampling.
func resizeNearest(src image.Image, tw, th int) *image.RGBA {
	dst := image.NewRGBA(image.Rect(0, 0, tw, th))
	b := src.Bounds()
	for y := 0; y < th; y++ {
		sy := b.Min.Y + y*b.Dy()/th
		for x := 0; x < tw; x++ {
			sx := b.Min.X + x*b.Dx()/tw
			dst.Set(x, y, src.At(sx, sy))
		}
	}
	return dst
}

// emitMediaMessage renders a received/sent media item into the conversation
// pane. When a thumbnail is present it is drawn inline above the caption.
func emitMediaMessage(convID [16]byte, sender string, meta common.MediaMetadata) {
	if program == nil {
		return
	}

	caption := formatMediaLine(meta)
	content := caption
	if art := renderThumbnail(meta.Thumbnail); art != "" {
		// Leading newline so the art starts at column 0, below the "sender:" prefix.
		content = "\n" + art + "\n" + caption
	}

	go program.Send(NetworkMsg{
		ConversationID: convID,
		SenderName:     sender,
		Content:        content,
		IsFile:         true,
	})
}

func formatMediaLine(meta common.MediaMetadata) string {
	icon := "\U0001F4CE" // 📎
	if strings.HasPrefix(meta.FileType, "image/") {
		icon = "\U0001F5BC" // 🖼
	}
	return fmt.Sprintf("%s %s (%s, %s)", icon, meta.FileName, meta.FileType, humanSize(meta.FileSize))
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGT"[exp])
}
