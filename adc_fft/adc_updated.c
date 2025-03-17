#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/spi/spidev.h>
#include <unistd.h>
#include <string.h>

#include "kiss_fftr.h"

#define FSAMP 50000       // Sample rate (Hz)
#define NSAMP 1000        // Number of samples
#define SPI_DEVICE "/dev/spidev0.0"  // SPI device
#define SPI_SPEED 1000000 // 1 MHz SPI speed

int spi_fd;  // File descriptor for SPI

// Function to initialize SPI
int init_spi() {
    spi_fd = open(SPI_DEVICE, O_RDWR);
    if (spi_fd < 0) {
        perror("Failed to open SPI device");
        return -1;
    }

    uint8_t mode = SPI_MODE_0;
    uint8_t bits = 8;
    uint32_t speed = SPI_SPEED;

    if (ioctl(spi_fd, SPI_IOC_WR_MODE, &mode) < 0) {
        perror("Failed to set SPI mode");
        return -1;
    }
    if (ioctl(spi_fd, SPI_IOC_WR_BITS_PER_WORD, &bits) < 0) {
        perror("Failed to set bits per word");
        return -1;
    }
    if (ioctl(spi_fd, SPI_IOC_WR_MAX_SPEED_HZ, &speed) < 0) {
        perror("Failed to set max speed");
        return -1;
    }

    return 0;
}

// Function to read ADC values using DMA
int read_adc_dma(uint8_t *buffer, size_t size) {
    uint8_t tx_buffer[size + 3];  // SPI command buffer
    memset(tx_buffer, 0, sizeof(tx_buffer));

    struct spi_ioc_transfer xfer = {
        .tx_buf = (unsigned long)tx_buffer,
        .rx_buf = (unsigned long)buffer,
        .len = size + 3, // Account for command bytes
        .speed_hz = SPI_SPEED,
        .bits_per_word = 8,
        .cs_change = 0
    };

    if (ioctl(spi_fd, SPI_IOC_MESSAGE(1), &xfer) < 0) {
        perror("SPI DMA Transfer failed");
        return -1;
    }

    return 0;
}

// Place this variable in the .hook section
__attribute__((section(".hook"))) volatile const char hook_marker[] = "HOOK_MARKER";

int main() {
    if (init_spi() < 0) {
        return 1;
    }

    uint8_t cap_buf[NSAMP];
    kiss_fft_scalar fft_in[NSAMP];
    kiss_fft_cpx fft_out[NSAMP / 2 + 1];

    kiss_fftr_cfg cfg = kiss_fftr_alloc(NSAMP, 0, NULL, NULL);
    if (!cfg) {
        fprintf(stderr, "Failed to allocate FFT configuration\n");
        return 1;
    }

    // Read ADC samples via DMA
    if (read_adc_dma(cap_buf, NSAMP) < 0) {
        return 1;
    }

    uint64_t sum = 0;
    for (int i=0;i<NSAMP;i++) {sum+=cap_buf[i];}
    float avg = (float)sum/NSAMP;

    // Convert input to FFT format
    for (int i = 0; i < NSAMP; i++) {
        fft_in[i] = (float)cap_buf[i] - avg; // Center around 0
    }

    // Perform FFT
    kiss_fftr(cfg, fft_in, fft_out);

    // Find the greatest frequency component
    int max_index = 0;
    float max_magnitude = 0;
    for (int i = 0; i < NSAMP / 2 + 1; i++) {
        float magnitude = sqrt(fft_out[i].r * fft_out[i].r + fft_out[i].i * fft_out[i].i);
        if (magnitude > max_magnitude) {
            max_magnitude = magnitude;
            max_index = i;
        }
    }
    printf("Greatest Frequency Component: %d Hz with magnitude %f\n", max_index * FSAMP / NSAMP, max_magnitude);

    free(cfg);
    close(spi_fd);
    return 0;
}
