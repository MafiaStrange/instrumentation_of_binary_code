run_no_aslr.sh temporarily disables ASLR when it is being executed 
config.ini stores the configuration file for instrumenting the code
For now let us just dry run the hookit.py code -> where we just get the details of branch and loops and not overwrite the binary

Run the following commands 

./run_no_aslr.sh python3 hookit.py -c config.ini --dry-run --create-branch-table --create-loop-table
aarch64-linux-gnu-gcc -static -o adc_fft_dma adc_updated.c kiss_fft.c kiss_fftr.c -lm -Wl,-T,linker.ld

If you do not want to dry run it, just remove the corresponding flag

output.bin contains the output of the hookit function --> basically the details of loops and branches

The c-flat implementation was being done on a 32-bit system, The corresponding changes were being for the 64-bit architecture.
