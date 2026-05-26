package handlers

import (
	"image"
	"image/color"
	"image/draw"
	"image/jpeg"
	"image/png"
	"log"
	"os"
	"strings"

	"golang.org/x/image/font"
	"golang.org/x/image/font/gofont/goitalic"
	"golang.org/x/image/font/opentype"
	"golang.org/x/image/math/fixed"
)

const watermarkLabel = "Hall's Photography"

// parsedFont is the raw TTF loaded once at startup.
var parsedFont *opentype.Font

func init() {
	f, err := opentype.Parse(goitalic.TTF)
	if err != nil {
		log.Printf("Warning: could not parse watermark font: %v", err)
		return
	}
	parsedFont = f
}

// applyWatermark reads srcPath, stamps a clearly-visible tiled watermark, and
// writes the result to dstPath as JPEG. Non-JPEG/PNG types are copied as-is.
func applyWatermark(srcPath, dstPath, mimeType string) error {
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	var img image.Image
	lower := strings.ToLower(mimeType)
	switch lower {
	case "image/jpeg", "image/jpg":
		img, err = jpeg.Decode(srcFile)
	case "image/png":
		img, err = png.Decode(srcFile)
	default:
		return copyFile(srcPath, dstPath)
	}
	if err != nil {
		return err
	}

	bounds := img.Bounds()
	rgba := image.NewRGBA(bounds)
	draw.Draw(rgba, bounds, img, bounds.Min, draw.Src)

	if parsedFont != nil {
		stampWatermarks(rgba)
	}

	dstFile, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	return jpeg.Encode(dstFile, rgba, &jpeg.Options{Quality: 88})
}

// stampWatermarks tiles "Hall's Photography" across the image at a size that
// is clearly visible regardless of the photo's resolution.
func stampWatermarks(img *image.RGBA) {
	bounds := img.Bounds()
	w := bounds.Max.X
	h := bounds.Max.Y

	fontSize := dynamicFontSize(w, h)
	face, err := opentype.NewFace(parsedFont, &opentype.FaceOptions{
		Size:    fontSize,
		DPI:     96,
		Hinting: font.HintingFull,
	})
	if err != nil {
		log.Printf("Warning: could not create watermark face: %v", err)
		return
	}

	adv     := font.MeasureString(face, watermarkLabel)
	textW   := adv.Ceil()
	textH   := int(fontSize * 1.4) // generous line height
	padX    := int(fontSize * 0.8)
	padY    := int(fontSize * 1.0)
	stepX   := textW + padX
	stepY   := textH + padY

	for row := -1; ; row++ {
		y := row * stepY
		if y > h+stepY {
			break
		}
		// Stagger alternate rows by half the step to create a diagonal illusion.
		xOff := 0
		if row%2 != 0 {
			xOff = stepX / 2
		}
		for col := -1; ; col++ {
			x := col*stepX + xOff
			if x > w+stepX {
				break
			}
			drawWatermarkAt(img, face, x, y+int(fontSize))
		}
	}
}

// dynamicFontSize returns a font size that is clearly legible on an image of
// the given pixel dimensions — roughly 5% of the shorter side.
func dynamicFontSize(w, h int) float64 {
	shorter := float64(w)
	if float64(h) < shorter {
		shorter = float64(h)
	}
	size := shorter * 0.05
	if size < 28 {
		size = 28
	}
	if size > 140 {
		size = 140
	}
	return size
}

// drawWatermarkAt renders the watermark text at (x, baseline) with a dark
// shadow beneath it for contrast on any background.
func drawWatermarkAt(img *image.RGBA, face font.Face, x, baseline int) {
	// Dark semi-transparent shadow for contrast against light backgrounds
	shadow := image.NewUniform(color.RGBA{R: 10, G: 5, B: 5, A: 160})
	offset := 3
	(&font.Drawer{
		Dst:  img,
		Src:  shadow,
		Face: face,
		Dot:  fixed.P(x+offset, baseline+offset),
	}).DrawString(watermarkLabel)

	// Main text — bright white at 210/255 opacity (clearly visible)
	main := image.NewUniform(color.RGBA{R: 255, G: 255, B: 255, A: 210})
	(&font.Drawer{
		Dst:  img,
		Src:  main,
		Face: face,
		Dot:  fixed.P(x, baseline),
	}).DrawString(watermarkLabel)
}

// copyFile copies src to dst byte-for-byte (used for unsupported image types).
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	buf := make([]byte, 32*1024)
	for {
		n, readErr := in.Read(buf)
		if n > 0 {
			if _, writeErr := out.Write(buf[:n]); writeErr != nil {
				return writeErr
			}
		}
		if readErr != nil {
			if readErr.Error() == "EOF" {
				break
			}
			return readErr
		}
	}
	return nil
}
