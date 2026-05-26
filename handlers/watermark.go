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

var watermarkFace font.Face

func init() {
	f, err := opentype.Parse(goitalic.TTF)
	if err != nil {
		log.Printf("Warning: could not parse watermark font: %v", err)
		return
	}
	face, err := opentype.NewFace(f, &opentype.FaceOptions{
		Size:    42,
		DPI:     72,
		Hinting: font.HintingFull,
	})
	if err != nil {
		log.Printf("Warning: could not create watermark font face: %v", err)
		return
	}
	watermarkFace = face
}

// applyWatermark reads srcPath, stamps the watermark, and writes the result to dstPath.
// Only JPEG and PNG are supported; other types are copied as-is.
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
		// Unsupported: copy original to dst so the path is still valid
		return copyFile(srcPath, dstPath)
	}
	if err != nil {
		return err
	}

	bounds := img.Bounds()
	rgba := image.NewRGBA(bounds)
	draw.Draw(rgba, bounds, img, bounds.Min, draw.Src)

	if watermarkFace != nil {
		tileWatermarks(rgba)
	}

	dstFile, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	return jpeg.Encode(dstFile, rgba, &jpeg.Options{Quality: 88})
}

// tileWatermarks stamps "Hall's Photography" in a repeating staggered grid.
func tileWatermarks(img *image.RGBA) {
	bounds := img.Bounds()
	w, h := bounds.Max.X, bounds.Max.Y

	adv := font.MeasureString(watermarkFace, watermarkLabel)
	textW := adv.Ceil() + 30 // horizontal step
	textH := 42 + 16         // vertical step (font size + padding)

	// Diagonal angle ~30°: each row shifts right by textW/2 so the grid looks diagonal.
	for row := -1; ; row++ {
		y := row * textH
		if y > h+textH {
			break
		}
		xOff := 0
		if row%2 != 0 {
			xOff = textW / 2
		}
		for col := -1; ; col++ {
			x := col*textW + xOff
			if x > w+textW {
				break
			}
			drawWatermarkAt(img, x, y+42) // baseline at y+fontsize
		}
	}
}

// drawWatermarkAt draws the watermark text at (x, baseline) with a shadow.
func drawWatermarkAt(img *image.RGBA, x, baseline int) {
	// Shadow — dark, subtle
	(&font.Drawer{
		Dst:  img,
		Src:  image.NewUniform(color.RGBA{0, 0, 0, 70}),
		Face: watermarkFace,
		Dot:  fixed.P(x+2, baseline+2),
	}).DrawString(watermarkLabel)

	// Main text — semi-transparent white
	(&font.Drawer{
		Dst:  img,
		Src:  image.NewUniform(color.RGBA{255, 255, 255, 150}),
		Face: watermarkFace,
		Dot:  fixed.P(x, baseline),
	}).DrawString(watermarkLabel)
}

// copyFile copies src to dst byte-for-byte.
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

