import speedtest

def measure_total_bandwidth():
    
    st = speedtest.Speedtest()
    
    print("Measuring download speed...")
    download_bps = st.download()   # bits per second
    
    print("Measuring upload speed...")
    upload_bps = st.upload()       # bits per second
    
    # convert to bytes per second
    download_bytes_per_sec = download_bps / 8
    upload_bytes_per_sec   = upload_bps   / 8
    
    print("Download = " + str(round(download_bps / 1024 / 1024, 2)) + " Mbps")
    print("Upload   = " + str(round(upload_bps   / 1024 / 1024, 2)) + " Mbps")
    
    return download_bytes_per_sec, upload_bytes_per_sec

download_pool, upload_pool = measure_total_bandwidth()
