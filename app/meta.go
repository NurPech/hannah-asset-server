package main

import (
	"encoding/binary"
	"io"
	"math"
	"os"
)

type AssetMeta struct {
	DurationS     *float64 `json:"duration_s,omitempty"`
	SampleRate    *int     `json:"sample_rate,omitempty"`
	Channels      *int     `json:"channels,omitempty"`
	BitsPerSample *int     `json:"bits_per_sample,omitempty"`
	Width         *int     `json:"width,omitempty"`
	Height        *int     `json:"height,omitempty"`
	ColorDepth    *int     `json:"color_depth,omitempty"`
}

func extractMeta(mimeType, filePath string) *AssetMeta {
	switch mimeType {
	case "audio/wav", "audio/wave", "audio/x-wav":
		return extractWAVMeta(filePath)
	case "image/png":
		return extractPNGMeta(filePath)
	case "image/jpeg":
		return extractJPEGMeta(filePath)
	}
	return nil
}

func extractWAVMeta(path string) *AssetMeta {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	hdr := make([]byte, 12)
	if _, err := io.ReadFull(f, hdr); err != nil {
		return nil
	}
	if string(hdr[0:4]) != "RIFF" || string(hdr[8:12]) != "WAVE" {
		return nil
	}

	var numChannels, sampleRate, bitsPerSample int
	var byteRate, dataSize uint32
	var hasFmt, hasData bool
	chunk := make([]byte, 8)

scan:
	for {
		if _, err := io.ReadFull(f, chunk); err != nil {
			break
		}
		id := string(chunk[0:4])
		size := binary.LittleEndian.Uint32(chunk[4:8])

		switch id {
		case "fmt ":
			if size < 16 {
				skip := int64(size)
				if size%2 != 0 {
					skip++
				}
				f.Seek(skip, io.SeekCurrent)
				break
			}
			data := make([]byte, 16)
			if _, err := io.ReadFull(f, data); err != nil {
				break scan
			}
			numChannels = int(binary.LittleEndian.Uint16(data[2:4]))
			sampleRate = int(binary.LittleEndian.Uint32(data[4:8]))
			byteRate = binary.LittleEndian.Uint32(data[8:12])
			bitsPerSample = int(binary.LittleEndian.Uint16(data[14:16]))
			hasFmt = true
			skip := int64(size) - 16
			if size%2 != 0 {
				skip++
			}
			if skip > 0 {
				f.Seek(skip, io.SeekCurrent)
			}
		case "data":
			dataSize = size
			hasData = true
		default:
			skip := int64(size)
			if size%2 != 0 {
				skip++
			}
			if _, err := f.Seek(skip, io.SeekCurrent); err != nil {
				break scan
			}
		}

		if hasFmt && hasData {
			break
		}
	}

	if !hasFmt {
		return nil
	}

	meta := &AssetMeta{
		Channels:      &numChannels,
		SampleRate:    &sampleRate,
		BitsPerSample: &bitsPerSample,
	}
	if hasData && byteRate > 0 {
		d := math.Round(float64(dataSize)/float64(byteRate)*100) / 100
		meta.DurationS = &d
	}
	return meta
}

func extractPNGMeta(path string) *AssetMeta {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	sig := make([]byte, 8)
	if _, err := io.ReadFull(f, sig); err != nil {
		return nil
	}
	if string(sig) != "\x89PNG\r\n\x1a\n" {
		return nil
	}

	// First chunk is always IHDR: length(4) + type(4) + data(13) + crc(4)
	var length uint32
	if err := binary.Read(f, binary.BigEndian, &length); err != nil {
		return nil
	}
	chunkType := make([]byte, 4)
	if _, err := io.ReadFull(f, chunkType); err != nil {
		return nil
	}
	if string(chunkType) != "IHDR" || length < 13 {
		return nil
	}

	ihdr := make([]byte, 13)
	if _, err := io.ReadFull(f, ihdr); err != nil {
		return nil
	}

	width := int(binary.BigEndian.Uint32(ihdr[0:4]))
	height := int(binary.BigEndian.Uint32(ihdr[4:8]))
	bitDepth := int(ihdr[8])
	colorType := ihdr[9]

	components := 1
	switch colorType {
	case 2:
		components = 3 // RGB
	case 4:
		components = 2 // grayscale + alpha
	case 6:
		components = 4 // RGBA
	}
	colorDepth := bitDepth * components

	return &AssetMeta{
		Width:      &width,
		Height:     &height,
		ColorDepth: &colorDepth,
	}
}

func extractJPEGMeta(path string) *AssetMeta {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var buf [2]byte
	if _, err := io.ReadFull(f, buf[:]); err != nil || buf[0] != 0xFF || buf[1] != 0xD8 {
		return nil
	}

	for {
		if _, err := io.ReadFull(f, buf[:]); err != nil {
			return nil
		}
		if buf[0] != 0xFF {
			return nil
		}
		marker := buf[1]
		// Skip fill bytes
		for marker == 0xFF {
			if _, err := io.ReadFull(f, buf[:1]); err != nil {
				return nil
			}
			marker = buf[0]
		}
		if marker == 0xD9 || marker == 0xDA {
			return nil
		}

		// Read segment length (includes the 2 length bytes itself)
		if _, err := io.ReadFull(f, buf[:]); err != nil {
			return nil
		}
		segLen := int(binary.BigEndian.Uint16(buf[:])) - 2

		isSOF := marker == 0xC0 || marker == 0xC1 || marker == 0xC2 || marker == 0xC3 ||
			marker == 0xC5 || marker == 0xC6 || marker == 0xC7 ||
			marker == 0xC9 || marker == 0xCA || marker == 0xCB

		if isSOF && segLen >= 6 {
			data := make([]byte, 6)
			if _, err := io.ReadFull(f, data); err != nil {
				return nil
			}
			precision := int(data[0])
			height := int(binary.BigEndian.Uint16(data[1:3]))
			width := int(binary.BigEndian.Uint16(data[3:5]))
			components := int(data[5])
			colorDepth := precision * components
			return &AssetMeta{
				Width:      &width,
				Height:     &height,
				ColorDepth: &colorDepth,
			}
		}

		if segLen > 0 {
			if _, err := f.Seek(int64(segLen), io.SeekCurrent); err != nil {
				return nil
			}
		}
	}
}
