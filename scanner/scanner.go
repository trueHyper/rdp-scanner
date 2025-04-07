package scanner

import (
	"fmt"
	"encoding/base64"
	"image"
	"image/color"
	"bytes"
	"log"
	"image/draw"
	//"image/png"
	"image/jpeg"
	//"os"
	//"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/trueHyper/rdp-scanner/core"
	//"github.com/tomatome/grdp/glog"
)


type Screen struct {
	Height int
	Width  int
}

type Info struct {
	Domain   string
	Ip       string
	Port     string
	Username string
	Passwd   string
	Screen
}

type Bitmap struct {
	DestLeft     int
	DestTop      int
	DestRight    int
	DestBottom   int
	Width        int
	Height       int
	BitsPerPixel int
	IsCompress   bool
	Data         []byte
}

type Control interface {
	Login() error
	Close()
}

var compressionRatio int = 70
//const inactivityTimeout = 2000 * time.Millisecond // ok

// RDPScann
func RDPScann(socket string, base64CompressRatio, bitmapUpdateTimeout, screenHeight, screenWidth int) {
	compressionRatio = base64CompressRatio
	
	var inactivityTimeout = new(time.Duration)
	*inactivityTimeout = time.Duration(bitmapUpdateTimeout) * time.Millisecond
	
	BitmapCH := make(chan []Bitmap, 500) // ok
	var lastBitmapTime = new(time.Time)
	var noActivityTimer *time.Timer
	var saveDone = make(chan struct{})
	var ScreenImage *image.RGBA
	updateBitmap := new(bool)
	*updateBitmap = false

	var SyncSave = make(chan string)
	var wg sync.WaitGroup
	var gc Control
	var i Info = Info{
		Ip:   strings.Split(socket, ":")[0],
		Port: strings.Split(socket, ":")[1],
	}

	i.Width = screenWidth
	i.Height = screenHeight

	ScreenImage = image.NewRGBA(image.Rect(0, 0, i.Width, i.Height))

	update := func(lastBitmapTime *time.Time, inactivityTimeout* time.Duration) {
		for {
			select {
			case bs := <-BitmapCH:
				*lastBitmapTime = time.Now()
				noActivityTimer.Reset(*inactivityTimeout)
				paint_bitmap(bs, ScreenImage, updateBitmap)
				//glog.Info(fmt.Sprintf("Received bitmap update at %v", lastBitmapTime.Format("15:04:05.000")))
			case <-saveDone:
				return
			}
		}
	}
	
	saveAndExit := func() {

		if noActivityTimer != nil {
			noActivityTimer.Stop()
		}

		saveImage(SyncSave, ScreenImage, updateBitmap)

		select {
		case <-saveDone:
		default:
			close(saveDone)
		}
	}

	wg.Add(1)
	go func(SyncSave chan string) {
		defer wg.Done()
		GetNtlmInfo(socket, SyncSave)
	}(SyncSave)

	_, gc = uiRdp(&i, BitmapCH)
	if gc != nil {
		defer gc.Close()
	}

	*lastBitmapTime = time.Now()

	noActivityTimer = time.AfterFunc(*inactivityTimeout, func() {
		if *updateBitmap {
			//glog.Info("No bitmap updates received for", inactivityTimeout, "- saving and exiting")
		}
		saveAndExit()

	})

	update(lastBitmapTime, inactivityTimeout)

	<-saveDone

	wg.Wait()
}

func paint_bitmap(bs []Bitmap, ScreenImage *image.RGBA, updateBitmap *bool) {
	*updateBitmap = true
	for _, bm := range bs {
		m := image.NewRGBA(image.Rect(0, 0, bm.Width, bm.Height))
		i := 0
		for y := 0; y < bm.Height; y++ {
			for x := 0; x < bm.Width; x++ {
				r, g, b, a := ToRGBA(bm.BitsPerPixel, i, bm.Data)
				m.Set(x, y, color.RGBA{r, g, b, a})
				i += bm.BitsPerPixel
			}
		}
		draw.Draw(ScreenImage, ScreenImage.Bounds().Add(image.Pt(bm.DestLeft, bm.DestTop)), m, m.Bounds().Min, draw.Src)
	}
}

func ToRGBA(pixel int, i int, data []byte) (r, g, b, a uint8) {
	a = 255
	switch pixel {
	case 1:
		rgb555 := core.Uint16BE(data[i], data[i+1])
		r, g, b = core.RGB555ToRGB(rgb555)
	case 2:
		rgb565 := core.Uint16BE(data[i], data[i+1])
		r, g, b = core.RGB565ToRGB(rgb565)
	case 3, 4:
		fallthrough
	default:
		r, g, b = data[i+2], data[i+1], data[i]
	}
	return
}

func saveImage(SyncSave chan string, ScreenImage *image.RGBA, updateBitmap *bool) {

	if !(*updateBitmap) {
		log.Println("i/o timeout, no bitmap after.. Screen is not saving.")
		select {
		case _, ok := <-SyncSave:
			if !ok {
				return
			}
		default:
			SyncSave <- ""
		}
		return
	}

	if ScreenImage == nil {
		SyncSave <- ""
		return
	}
	
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, ScreenImage, &jpeg.Options{Quality: compressionRatio}); err != nil {
		SyncSave <- ""
		return
	}
	//if err := png.Encode(&buf, ScreenImage); err != nil {
	//	SyncSave <- ""
	//	return
	//}

	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())
	
	
	fmt.Println(encoded)

	select {
	case _, ok := <-SyncSave:
		if !ok {
			fmt.Println("Канал закрыт и пуст!")
			return
		}
	default:
		SyncSave <- encoded
	}
	//glog.Info("Screenshot saved to:", filename)
}

func Bpp(BitsPerPixel uint16) int {
	switch BitsPerPixel {
	case 15:
		return 1
	case 16:
		return 2
	case 24:
		return 3
	case 32:
		return 4
	default:
		//glog.Error("invalid bitmap data format")
		return 4
	}
}

func Hex2Dec(val string) int {
	n, err := strconv.ParseUint(val, 16, 32)
	if err != nil {
		fmt.Println(err)
	}
	return int(n)
}
