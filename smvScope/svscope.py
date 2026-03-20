#!/usr/bin/env python3

import os,sys
import ctypes
import time
from smvScope import lib61850
import json
import types
import io
import zipfile

from flask import Flask, Response, render_template, request, send_file

import socket
from struct import unpack, pack
import threading
import binascii
from collections import deque
from datetime import datetime

application = Flask(__name__)


control_data_d = {}
control_data_d_update = True

# streamlistener data
streamListingThread = threading.Thread()
streamList = []
StreamDetails = {}

#stream data
subscribers_list = []
# subscribe/unsibscribe data
receiver = None
subscribers = {}
streamFilter = {}

# subscriber callback data
smv_data = {}
sec_counter = {}
streamInfo = {}
oldSmpCnt = {}
communicationStats = {}
networkInfo = {}

log_list = []

QUALITY_VALIDITY_LABELS = {
    getattr(lib61850, 'QUALITY_VALIDITY_GOOD', 0): 'good',
    getattr(lib61850, 'QUALITY_VALIDITY_RESERVED', 1): 'reserved',
    getattr(lib61850, 'QUALITY_VALIDITY_INVALID', 2): 'invalid',
    getattr(lib61850, 'QUALITY_VALIDITY_QUESTIONABLE', 3): 'questionable',
}

QUALITY_FLAGS = [
    ('overflow', getattr(lib61850, 'QUALITY_DETAIL_OVERFLOW', 4)),
    ('outOfRange', getattr(lib61850, 'QUALITY_DETAIL_OUT_OF_RANGE', 8)),
    ('badReference', getattr(lib61850, 'QUALITY_DETAIL_BAD_REFERENCE', 16)),
    ('oscillatory', getattr(lib61850, 'QUALITY_DETAIL_OSCILLATORY', 32)),
    ('failure', getattr(lib61850, 'QUALITY_DETAIL_FAILURE', 64)),
    ('oldData', getattr(lib61850, 'QUALITY_DETAIL_OLD_DATA', 128)),
    ('inconsistent', getattr(lib61850, 'QUALITY_DETAIL_INCONSISTENT', 256)),
    ('inaccurate', getattr(lib61850, 'QUALITY_DETAIL_INACCURATE', 512)),
    ('substituted', getattr(lib61850, 'QUALITY_SOURCE_SUBSTITUTED', 1024)),
    ('test', getattr(lib61850, 'QUALITY_TEST', 2048)),
    ('operatorBlocked', getattr(lib61850, 'QUALITY_OPERATOR_BLOCKED', 4096)),
    ('derived', getattr(lib61850, 'QUALITY_DERIVED', 8192)),
]

SMP_SYNC_LABELS = {
    0: 'none',
    1: 'local',
    2: 'global',
    3: 'unknown',
}

# listbox data
control_data_d['streamSelect_items'] = [] # list of streams
control_data_d['streamSelect'] = { "streamValue": [], "enableListener": True } # selected stream


def _decode_quality(quality_value):
    validity = quality_value & 0x3
    active_flags = [name for name, bitmask in QUALITY_FLAGS if quality_value & bitmask]

    if validity == getattr(lib61850, 'QUALITY_VALIDITY_GOOD', 0) and not active_flags:
        state = 'good'
    elif validity == getattr(lib61850, 'QUALITY_VALIDITY_INVALID', 2) or 'failure' in active_flags or 'badReference' in active_flags:
        state = 'invalid'
    else:
        state = 'warning'

    return {
        'value': int(quality_value),
        'hex': f"0x{int(quality_value):04x}",
        'validity': QUALITY_VALIDITY_LABELS.get(validity, f'unknown({validity})'),
        'flags': active_flags,
        'state': state,
    }


def _build_lsvs_status(asdu, size):
    channel_count = int(size / 8) if size > 0 else 0
    channels = {}
    overall_state = 'good'

    for channel in range(channel_count):
        quality_offset = channel * 8 + 4
        if quality_offset + 4 > size:
            continue

        quality = int(lib61850.SVSubscriber_ASDU_getQuality(asdu, quality_offset))
        decoded = _decode_quality(quality)
        channels[channel] = decoded

        if decoded['state'] == 'invalid':
            overall_state = 'invalid'
        elif decoded['state'] == 'warning' and overall_state == 'good':
            overall_state = 'warning'

    smp_sync = int(lib61850.SVSubscriber_ASDU_getSmpSynch(asdu))
    return {
        'overall': overall_state,
        'channelCount': channel_count,
        'smpSync': smp_sync,
        'smpSyncLabel': SMP_SYNC_LABELS.get(smp_sync, f'unknown({smp_sync})'),
        'channels': channels,
    }


def _get_interface_name():
    return sys.argv[1] if len(sys.argv) > 1 else 'eth0'


def _read_text_file(path):
    try:
        with open(path, 'r', encoding='utf-8') as handle:
            return handle.read().strip()
    except OSError:
        return None


def _read_network_info(interface):
    base_path = f'/sys/class/net/{interface}'
    speed_text = _read_text_file(f'{base_path}/speed')
    mtu_text = _read_text_file(f'{base_path}/mtu')
    carrier_text = _read_text_file(f'{base_path}/carrier')
    operstate = _read_text_file(f'{base_path}/operstate')
    duplex = _read_text_file(f'{base_path}/duplex')

    try:
        speed_mbps = int(speed_text)
        if speed_mbps < 0:
            speed_mbps = None
    except (TypeError, ValueError):
        speed_mbps = None

    try:
        mtu = int(mtu_text) if mtu_text is not None else None
    except ValueError:
        mtu = None

    return {
        'interface': interface,
        'speedMbps': speed_mbps,
        'carrier': carrier_text == '1' if carrier_text in ('0', '1') else None,
        'operState': operstate or 'unknown',
        'duplex': duplex or 'unknown',
        'mtu': mtu,
    }


def _mean(values):
    return (sum(values) / len(values)) if values else None


def _new_qos_stats():
    return {
        'packetsReceived': 0,
        'packetsLost': 0,
        'lossPercent': 0.0,
        'bandwidthBps': 0.0,
        'packetRatePps': 0.0,
        'jitterMs': None,
        'propagationDelayMs': None,
        'minDelayMs': None,
        'maxDelayMs': None,
        'lastArrivalMs': None,
        'lastRefTimeMs': None,
        'lastSmpCnt': None,
        'lastIntervalMs': None,
        'windowBytes': 0,
        'arrivalWindow': deque(),
        'jitterWindow': deque(maxlen=128),
        'delayWindow': deque(maxlen=128),
    }


def _normalize_sample_delta(previous, current, sample_rate):
    if previous is None:
        return None
    if current >= previous:
        return current - previous
    if sample_rate and sample_rate > 0:
        return (sample_rate - previous) + current
    return 1


def _update_qos_metrics(svID, packet_size, smpCnt, sample_rate, ref_time_ms):
    global communicationStats

    arrival_ms = time.time() * 1000.0
    stats = communicationStats.setdefault(svID, _new_qos_stats())
    stats['packetsReceived'] += 1

    sample_delta = _normalize_sample_delta(stats['lastSmpCnt'], smpCnt, sample_rate)
    if sample_delta is not None and sample_delta > 1:
        stats['packetsLost'] += sample_delta - 1

    total_packets = stats['packetsReceived'] + stats['packetsLost']
    if total_packets > 0:
        stats['lossPercent'] = (stats['packetsLost'] * 100.0) / total_packets

    if stats['lastArrivalMs'] is not None:
        interval_ms = arrival_ms - stats['lastArrivalMs']
        if stats['lastIntervalMs'] is not None:
            stats['jitterWindow'].append(abs(interval_ms - stats['lastIntervalMs']))
        stats['lastIntervalMs'] = interval_ms
        stats['jitterMs'] = _mean(stats['jitterWindow'])

    stats['arrivalWindow'].append((arrival_ms, packet_size))
    stats['windowBytes'] += packet_size
    cutoff_ms = arrival_ms - 1000.0
    while stats['arrivalWindow'] and stats['arrivalWindow'][0][0] < cutoff_ms:
        _, old_size = stats['arrivalWindow'].popleft()
        stats['windowBytes'] -= old_size

    if stats['arrivalWindow']:
        window_duration_ms = max(arrival_ms - stats['arrivalWindow'][0][0], 1.0)
        stats['packetRatePps'] = (len(stats['arrivalWindow']) * 1000.0) / window_duration_ms
        stats['bandwidthBps'] = (stats['windowBytes'] * 8.0 * 1000.0) / window_duration_ms

    if ref_time_ms is not None:
        delay_ms = arrival_ms - ref_time_ms
        stats['delayWindow'].append(delay_ms)
        stats['propagationDelayMs'] = _mean(stats['delayWindow'])
        stats['minDelayMs'] = min(stats['delayWindow'])
        stats['maxDelayMs'] = max(stats['delayWindow'])
        stats['lastRefTimeMs'] = ref_time_ms

    stats['lastArrivalMs'] = arrival_ms
    stats['lastSmpCnt'] = smpCnt

    return {
        'packetsReceived': stats['packetsReceived'],
        'packetsLost': stats['packetsLost'],
        'lossPercent': round(stats['lossPercent'], 4),
        'bandwidthBps': round(stats['bandwidthBps'], 2),
        'packetRatePps': round(stats['packetRatePps'], 2),
        'jitterMs': round(stats['jitterMs'], 4) if stats['jitterMs'] is not None else None,
        'propagationDelayMs': round(stats['propagationDelayMs'], 4) if stats['propagationDelayMs'] is not None else None,
        'minDelayMs': round(stats['minDelayMs'], 4) if stats['minDelayMs'] is not None else None,
        'maxDelayMs': round(stats['maxDelayMs'], 4) if stats['maxDelayMs'] is not None else None,
    }


# duration can be > 0 to set a timeout, 0 for immediate and -1 for infinite
def getSMVStreams(interface, duration):
    global streamList
    global StreamDetails
    #Convert a string of 6 characters of ethernet address into a dash separated hex string
    def eth_addr (a) :
        b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % ((a[0]) , (a[1]) , (a[2]), (a[3]), (a[4]) , (a[5]))
        return b

    ret =  os.system("ifconfig %s promisc" % interface)
    if ret != 0:
        print_to_log("error setting promiscuous mode on %s" % sys.argv[1])
        sys.exit(-1)

    #create an INET, raw socket
    #define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */
    # SMV                0x88ba
    # GOOSE              0x88b8
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x88ba))
    #s.setsockopt(socket.SOL_SOCKET, 25, str(interface + '\0').encode('utf-8'))
    s.bind((interface,0))

    streams = []

    # handle duration
    if duration < 0:
        s.settimeout(1)        
    if duration == 0:
        s.settimeout(0)
        s.setblocking(0)
    if duration > 0:
        s.settimeout(1)
        deadline = time.perf_counter() + duration

    print("streamListingThread started!")
    while control_data_d["streamSelect"]["enableListener"] == True:
        if duration > 0 and time.perf_counter() > deadline:
            break
        try:
            packet = s.recvfrom(65565)
        except:
            continue

        #packet string from tuple
        packet = packet[0]
        #parse ethernet header
        eth_length = 14
        dst = eth_addr(packet[0:6])
        src = eth_addr(packet[6:12])
        # parse GOOSE streams, and make a list of them (record appid, MAC, gocbRef, )
        # when an element is chosen, the subscriber can be initialised
        # when a different element is chosen, re-init subscriber with new gocbRef    
        appid = unpack('!H' , packet[eth_length:eth_length+2] )[0]

        svID_length = 31
        svID_size = int(packet[svID_length + 1])
        svID = packet[svID_length + 2 : svID_length + 2 + svID_size].decode("utf-8")
        #print_to_log("mac: %s, appid: %i, gocbRef: %s, gocbRef_size: %i" % (dst, appid, gocbRef, gocbRef_size))
        #item = "%s %i %s" % (dst,appid,gocbRef)
        if svID not in StreamDetails:
            StreamDetails[svID] = {'src': src, 'dst': dst, 'appid': appid}
        else:
            if StreamDetails[svID]['src'] != src or StreamDetails[svID]['dst'] != dst:
                print_to_log("ERROR: goose collision! message received with matching gocbref: %s but;" % svID)
                if StreamDetails[svID]['src'] != src:
                    print_to_log("  src mac not matching: expected: %s, received: %s" % (StreamDetails[svID]['src'], src))
                if StreamDetails[svID]['dst'] != dst:
                    print_to_log("  dst mac not matching: expected: %s, received: %s" % (StreamDetails[svID]['dst'], dst))               
                if StreamDetails[svID]['appid'] != appid:
                    print_to_log("  appid not matching: expected: %s, received: %s" % (StreamDetails[svID]['appid'], appid))
                print_to_log("NOTE: gocbref are expected to be unique for each stream")

        for channel in range(8):# TODO: base range on decoded size
            item = "%s,%i" % (svID,channel)
            if item not in streams:
                streams.append(item)

        if duration == 0:
            break
        if duration < 0:
            streamList = streams

    s.close()
    print("streamListingThread stopped!")
    return streams


@application.route('/')
def index():
    global control_data_d_update
    control_data_d_update = True
    return render_template('index.html')


def update_setting(subject, control, value):
    global control_data_d_update
    global control_data_d
    if control == "enableListener":
        global streamListingThread
        if value == True:
            if streamListingThread == None or streamListingThread.is_alive() == False:
                streamListingThread = threading.Thread(target=getSMVStreams, args=(sys.argv[1],-1))
                streamListingThread.start()
        control_data_d[subject][control] = value 
        control_data_d_update = True
        return True
    if control == "streamValue":
        global streamList
        global subscribers_list
        global receiver
        global smv_data

        dif_off = set(subscribers_list) - set(value)
        dif_on = set(value) - set(subscribers_list)
        #print_to_log(dif_off)
        #print_to_log(dif_on)
        for item in dif_off:
            stream = streamList[int(item)-1].split(',') # svID from itemlist
            svID = stream[0]
            channel = int(stream[1])
            unsubscribe(receiver, svID, channel, start = True)
            print_to_log("INFO: SMV item %s unsubscribed" % item)
        for item in dif_on:
            stream = streamList[int(item)-1].split(',') # svID from itemlist
            svID = stream[0]
            channel = int(stream[1])

            if svID not in smv_data:
                sec_counter[svID] = 0
                smv_data[svID] = {} # ensure we initialised the dataset
                smv_data[svID][0] = []
                oldSmpCnt[svID] = 0
            subscribe(receiver, svID, channel, start = True)
        # differences have been processed, value is the actual state
        subscribers_list = value

        if lib61850.SVReceiver_isRunning(receiver) == False:
            print_to_log("ERROR: Failed to enable SMV subscriber")
        else:# set control-data in the client control if succesfull
            control_data_d[subject][control] = value 
        # update the control now
        control_data_d_update = True
        return True
    return False


@application.route('/control-setting', methods=['POST'])
def control_setting(): # post requests with data from client-side javascript events
    global control_data_d
    content = request.get_json(silent=True)
    if content['id'] == "refresh":
        global control_data_d_update
        control_data_d_update = True
    else:
        for subject in control_data_d:
            if isinstance(control_data_d[subject], dict):    
                for item in control_data_d[subject]:
                    if item == content['id']:
                        if update_setting(subject, content['id'],content['value']) != True: # update the setting
                            print_to_log("ERROR: could not update setting: " + content['id'])
    return json.dumps({'success':True}), 200, {'ContentType':'application/json'} 


def control_data_g():
    global control_data_d
    global control_data_d_update
    global streamList
    streamList_Length = 0
    while True:
        time.sleep(0.1) # check for changes every 0.1 seconds, and if so send update to client

        # update the stream list, if a new entry is found
        if len(streamList) > streamList_Length:
            control_data_d['streamSelect_items'] = []
            for stream in streamList:
                control_data_d['streamSelect_items'].append(stream)
            streamList_Length = len(streamList)
            control_data_d_update = True

        # update the controls when a control is updated
        if control_data_d_update == True:
            control_data_d_update = False
            json_data = json.dumps(control_data_d)
            yield f"data:{json_data}\n\n"


@application.route('/control-data')
def control_data():
    return Response(control_data_g(), mimetype='text/event-stream')


def stream_data_g():
    global smv_data
    global streamInfo
    global sec_counter
    global streamFilter

    second_update = 0
    while True:
        allData = {}
        allData['dataSets'] = {}
        allData['stream_info'] = {}
        allData['network_info'] = networkInfo
        new_data = False

        index = 0
        for svID in streamFilter:
            second = sec_counter[svID] - 1
            if second < 1: #ignore the first 2 seconds, so items can be initialised
                continue
            if index == 0 and second > second_update: # check for the first active item if second was incremented
                second_update = second # reset it until next increment
                new_data = True # record data from all datasets

            #if we have new data
            if new_data == True:
                allData['dataSets'][svID] = smv_data[svID][second]
                allData['stream_info'][svID] = streamInfo[svID]
            index = index + 1

        if new_data == True:
            json_data = json.dumps(allData)
            yield f"data:{json_data}\n\n"
            new_data = False
        time.sleep(0.1) 

@application.route('/stream-data')
def stream_data():
    return Response(stream_data_g(), mimetype='text/event-stream')


def _sanitize_filename_part(value):
    return ''.join(ch if ch.isalnum() or ch in ('-', '_') else '_' for ch in value).strip('_') or 'stream'


def _get_selected_stream_channels():
    selected = {}
    for item in subscribers_list:
        try:
            stream = streamList[int(item) - 1].split(',')
            svID = stream[0]
            channel = int(stream[1])
        except (IndexError, ValueError):
            continue
        selected.setdefault(svID, set()).add(channel)
    return selected


def _get_latest_complete_samples(svID):
    if svID not in sec_counter or sec_counter[svID] < 2 or svID not in smv_data:
        return []
    latest_second = sec_counter[svID] - 1
    return smv_data[svID].get(latest_second, [])


def _estimate_sample_rate(samples, metadata):
    if metadata and 'smpRate' in metadata:
        try:
            return int(metadata['smpRate'])
        except (TypeError, ValueError):
            pass

    sample_numbers = [sample.get('x', 0) for sample in samples]
    max_sample = max(sample_numbers) if sample_numbers else 0
    if max_sample in (4000, 4800):
        return max_sample
    if len(samples) in (4000, 4800):
        return len(samples)
    return max_sample or len(samples) or 4000


def _estimate_nominal_frequency(sample_rate):
    if sample_rate == 4000:
        return 50
    if sample_rate == 4800:
        return 60
    return 0


def _get_channel_plot_scale(channel):
    return 1000.0 if channel < 4 else 100.0


def _channel_scaling(values, data_format):
    if not values:
        if data_format == 'ASCII':
            return 1.0, 0.0, 0, 65535
        return 1.0, 0.0, -32767, 32767

    minimum = min(values)
    maximum = max(values)
    if minimum == maximum:
        if data_format == 'ASCII':
            return 1.0, minimum, 0, 65535
        return 1.0, 0.0, minimum, maximum

    if data_format == 'ASCII':
        scale = (maximum - minimum) / 65535.0
        offset = minimum
        return scale, offset, 0, 65535

    offset = (maximum + minimum) / 2.0
    scale = (maximum - minimum) / 65534.0
    if scale == 0:
        scale = 1.0
    return scale, offset, minimum, maximum


def _encode_raw_value(value, channel):
    if channel['format'] == 'ASCII':
        raw = int(round((value - channel['b']) / channel['a'])) if channel['a'] != 0 else 0
        return max(0, min(65535, raw))

    raw = int(round((value - channel['b']) / channel['a'])) if channel['a'] != 0 else 0
    return max(-32767, min(32767, raw))


def _build_cfg_text(station_name, recorder_id, revision_year, analog_channels, sample_rate, start_time, trigger_time, data_format):
    analog_count = len(analog_channels)
    lines = []
    if revision_year == '1991':
        lines.append(f"{station_name},{recorder_id}")
    else:
        lines.append(f"{station_name},{recorder_id},{revision_year}")

    lines.append(f"{analog_count},{analog_count}A,0D")

    for index, channel in enumerate(analog_channels, start=1):
        lines.append(
            f"{index},{channel['name']},{channel['phase']},,{channel['unit']},{channel['a']:.12g},{channel['b']:.12g},0.0,"
            f"{channel['minimum']},{channel['maximum']}"
        )

    lines.append(f"{float(_estimate_nominal_frequency(sample_rate)):.1f}")
    lines.append("1")
    lines.append(f"{float(sample_rate):.1f},{len(channel['samples']) if analog_channels else 0}")
    lines.append(start_time.strftime("%m/%d/%y,%H:%M:%S.%f"))
    lines.append(trigger_time.strftime("%m/%d/%y,%H:%M:%S.%f"))
    lines.append(data_format)
    return "\n".join(lines) + "\n"


def _build_ascii_dat(analog_channels, sample_rate):
    rows = []
    sample_count = len(analog_channels[0]['samples']) if analog_channels else 0
    for sample_index in range(sample_count):
        timestamp_us = int(round(sample_index * 1000000.0 / sample_rate))
        values = [
            str(_encode_raw_value(analog_channels[channel_index]['samples'][sample_index], analog_channels[channel_index]))
            for channel_index in range(len(analog_channels))
        ]
        rows.append(",".join([str(sample_index + 1), str(timestamp_us)] + values))
    return ("\n".join(rows) + "\n").encode('ascii')


def _build_binary_dat(analog_channels, sample_rate):
    payload = bytearray()
    sample_count = len(analog_channels[0]['samples']) if analog_channels else 0

    for sample_index in range(sample_count):
        timestamp_us = int(round(sample_index * 1000000.0 / sample_rate))
        payload.extend(pack('<ii', sample_index + 1, timestamp_us))
        for channel in analog_channels:
            raw = _encode_raw_value(channel['samples'][sample_index], channel)
            payload.extend(pack('<h', raw))
    return bytes(payload)


@application.route('/export-comtrade', methods=['POST'])
def export_comtrade():
    payload = request.get_json(silent=True) or {}
    revision_year = str(payload.get('standard', '2013'))
    data_format = str(payload.get('format', 'ASCII')).upper()

    if revision_year not in ('1991', '1999', '2013'):
        return json.dumps({'success': False, 'error': 'Unsupported COMTRADE standard'}), 400, {'ContentType': 'application/json'}
    if data_format not in ('ASCII', 'BINARY'):
        return json.dumps({'success': False, 'error': 'Unsupported COMTRADE data format'}), 400, {'ContentType': 'application/json'}

    selected = _get_selected_stream_channels()
    if not selected:
        return json.dumps({'success': False, 'error': 'Select at least one stream/channel before exporting'}), 400, {'ContentType': 'application/json'}

    analog_channels = []
    sample_rate = None
    for svID in sorted(selected):
        samples = _get_latest_complete_samples(svID)
        if not samples:
            continue

        metadata = streamInfo.get(svID, {})
        current_sample_rate = _estimate_sample_rate(samples, metadata)
        if sample_rate is None:
            sample_rate = current_sample_rate

        channel_samples = {}
        for sample in samples:
            for channel, channel_data in sample.get('channels', {}).items():
                channel_index = int(channel)
                if channel_index in selected[svID]:
                    channel_samples.setdefault(channel_index, []).append(channel_data['y'])

        for channel in sorted(channel_samples):
            values = channel_samples[channel]
            if not values:
                continue
            plot_scale = _get_channel_plot_scale(channel)
            plotted_values = [value / plot_scale for value in values]
            unit = 'A' if channel < 4 else 'V'
            a, b, minimum, maximum = _channel_scaling(plotted_values, data_format)
            analog_channels.append({
                'name': f"{svID}_ch{channel}",
                'samples': plotted_values,
                'a': a,
                'b': b,
                'minimum': minimum,
                'maximum': maximum,
                'unit': unit,
                'phase': (channel % 4) + 1,
                'format': data_format,
            })

    if not analog_channels:
        return json.dumps({'success': False, 'error': 'No completed samples available yet for the selected streams/channels'}), 400, {'ContentType': 'application/json'}

    min_length = min(len(channel['samples']) for channel in analog_channels)
    analog_channels = [
        {**channel, 'samples': channel['samples'][:min_length]}
        for channel in analog_channels
    ]
    sample_rate = sample_rate or 4000

    export_time = datetime.now()
    station_name = 'smvScope'
    recorder_id = 'SMV'
    base_name = f"smvscope_{revision_year}_{data_format.lower()}_{export_time.strftime('%Y%m%d_%H%M%S')}"
    cfg_text = _build_cfg_text(station_name, recorder_id, revision_year, analog_channels, sample_rate, export_time, export_time, data_format)
    dat_content = _build_ascii_dat(analog_channels, sample_rate) if data_format == 'ASCII' else _build_binary_dat(analog_channels, sample_rate)

    archive = io.BytesIO()
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"{base_name}.cfg", cfg_text)
        zf.writestr(f"{base_name}.dat", dat_content)
    archive.seek(0)

    return send_file(
        archive,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f"{_sanitize_filename_part(base_name)}.zip"
    )

def print_to_log(message):
    global log_list
    log_list.append(message)

def log_data_g():
    global log_list
    log_length = 0
    while True:
        if len(log_list) > log_length:
            json_data = json.dumps(log_list[log_length : ])
            log_length = len(log_list)
            yield f"data:{json_data}\n\n"
        time.sleep(0.3)

@application.route('/log-data')
def log_data():
    return Response(log_data_g(), mimetype='text/event-stream')



def svUpdateListener_cb(subscriber, parameter, asdu):
    svID = lib61850.SVSubscriber_ASDU_getSvId(asdu).decode("utf-8")

    global streamFilter
    global streamInfo
    if svID not in streamFilter:
        print_to_log("DEBUG: filter not matched for svID: " + svID)
        return

    #print_to_log("SMV event: (svID: %s)" % svID)
    global smv_data
    global sec_counter
    global oldSmpCnt

    seconds = sec_counter[svID]
    size = lib61850.SVSubscriber_ASDU_getDataSize(asdu)
    smpCnt = lib61850.SVSubscriber_ASDU_getSmpCnt(asdu)
    #print_to_log("  confRev: %u" % lib61850.SVSubscriber_ASDU_getConfRev(asdu))
    #print_to_log("  smpSynch: %u" % lib61850.SVSubscriber_ASDU_getSmpSynch(asdu))

    # list with all y values (4x amp and 4x volt for 9-2 LE)
    indices = {}
    for channel in streamFilter[svID]:
        if channel * 8 < size:
            indices[channel] =  {'y': lib61850.SVSubscriber_ASDU_getINT32(asdu, channel * 8) }
        else:
            print_to_log("ERROR: cannot retrieve channel %i for svID: %s, size = %i" % (channel,svID,size)) 

    # json list with { x: samplecount, index: [{y:_},{y:_},{y:_},...] }
    smv_data[svID][seconds].append( {'x': smpCnt, 'channels': indices } )

    lsvs_status = _build_lsvs_status(asdu, size)

    ref_time_ms = None
    if lib61850.SVSubscriber_ASDU_hasRefrTm(asdu) == True:
        ref_time_ms = lib61850.SVSubscriber_ASDU_getRefrTmAsMs(asdu)

    sample_rate = None
    if lib61850.SVSubscriber_ASDU_hasSmpRate(asdu) == True:
        sample_rate = lib61850.SVSubscriber_ASDU_getSmpRate(asdu)
    elif svID in streamInfo and 'smpRate' in streamInfo[svID]:
        sample_rate = streamInfo[svID]['smpRate']

    qos_metrics = _update_qos_metrics(svID, size, smpCnt, sample_rate, ref_time_ms)

    if svID not in streamInfo:
        streamInfo[svID] = {
            'size': size,
            'seconds': seconds,
            'svID': svID,
            'confRev': lib61850.SVSubscriber_ASDU_getConfRev(asdu),
            'smpSync': lsvs_status['smpSync'],
            'lsvs': lsvs_status,
            'qos': qos_metrics,
        }
        if svID in StreamDetails:
            streamInfo[svID].update(StreamDetails[svID])
        if lib61850.SVSubscriber_ASDU_hasDatSet(asdu) == True:
            dataset = lib61850.SVSubscriber_ASDU_getDatSet(asdu)
            streamInfo[svID]['datset'] = dataset.decode("utf-8") if dataset else ''
        if sample_rate is not None:
            streamInfo[svID]['smpRate'] = sample_rate
        if ref_time_ms is not None:
            streamInfo[svID]['RefTm'] = ref_time_ms
        if lib61850.SVSubscriber_ASDU_hasSmpMod(asdu) == True:
            streamInfo[svID]['smpMod'] = lib61850.SVSubscriber_ASDU_getSmpMod(asdu)

    # increment the secod counter each 4000 sampled, i.e each second
    if oldSmpCnt[svID] > smpCnt: # trigger second increment when the counter loops.(i.e. when the previous smpCnt is higher then the current, we assume we looped around from 4000 to 0)
        streamInfo[svID]['size'] = size
        streamInfo[svID]['seconds'] = seconds
        streamInfo[svID]['svID'] = svID
        streamInfo[svID]['confRev'] = lib61850.SVSubscriber_ASDU_getConfRev(asdu)
        streamInfo[svID]['smpSync'] = lsvs_status['smpSync']
        streamInfo[svID]['lsvs'] = lsvs_status
        streamInfo[svID]['qos'] = qos_metrics
        if svID in StreamDetails:
            streamInfo[svID].update(StreamDetails[svID])

        # OPTIONAL; not in 9-2 LE, source:https://knowledge.rtds.com/hc/en-us/article_attachments/360074685173/C_Kriger_Adewole_RTDS.pdf
        if lib61850.SVSubscriber_ASDU_hasDatSet(asdu) == True:
            dataset = lib61850.SVSubscriber_ASDU_getDatSet(asdu)
            streamInfo[svID]['datset'] = dataset.decode("utf-8") if dataset else ''
        if sample_rate is not None:
            streamInfo[svID]['smpRate'] = sample_rate
        if ref_time_ms is not None:
            streamInfo[svID]['RefTm'] = ref_time_ms
        if lib61850.SVSubscriber_ASDU_hasSmpMod(asdu) == True:
            streamInfo[svID]['smpMod'] = lib61850.SVSubscriber_ASDU_getSmpMod(asdu)

        #increment counter
        seconds = seconds + 1
        smv_data[svID][seconds] = [] # create a new list to store the samples
        sec_counter[svID] = seconds
    else:
        streamInfo[svID]['seconds'] = seconds
        streamInfo[svID]['smpSync'] = lsvs_status['smpSync']
        streamInfo[svID]['lsvs'] = lsvs_status
        streamInfo[svID]['qos'] = qos_metrics
        if svID in StreamDetails:
            streamInfo[svID].update(StreamDetails[svID])
        if sample_rate is not None:
            streamInfo[svID]['smpRate'] = sample_rate
        if ref_time_ms is not None:
            streamInfo[svID]['RefTm'] = ref_time_ms
                             
    oldSmpCnt[svID] = smpCnt
    

# make the callback pointer global to prevent cleanup
svUpdateListener = lib61850.SVUpdateListener(svUpdateListener_cb)


def subscribe(receiver, svID, channel, start = True):
    global streamFilter
    global StreamDetails
    global subscribers

    # check if appid already in use in other filters
    inuse = False
    appid = StreamDetails[svID]['appid']
    for key in streamFilter:
        if StreamDetails[key]['appid'] == appid:
            inuse = True

    # if appid not yet subscribed to, subscribe
    if inuse == False:
        global svUpdateListener
        if lib61850.SVReceiver_isRunning(receiver) == True:
            lib61850.SVReceiver_stop(receiver)
        subscriber = lib61850.SVSubscriber_create(None, appid)
        subscribers[appid] = subscriber

        lib61850.SVSubscriber_setListener(subscriber, svUpdateListener, None)
        lib61850.SVReceiver_addSubscriber(receiver, subscriber)
        streamFilter[svID] = set()

        if start == True:
            lib61850.SVReceiver_start(receiver)
            if lib61850.SVReceiver_isRunning(receiver) ==  False:
                print_to_log("Failed to start SMV subscriber. Reason can be that the Ethernet interface doesn't exist or root permission are required.")
                sys.exit(-1)

    # add the filter
    streamFilter[svID].add(channel)

    print_to_log("INFO: SMV subscribed with: %i %s %i" % (appid, svID, channel))


def unsubscribe(receiver, svID, channel, start = True):
    global streamFilter
    global StreamDetails
    global subscribers

    streamFilter[svID].remove(channel)
    if len(streamFilter[svID]) == 0:
        streamFilter.pop(svID) # remove filter
        # check if appid still in use in other filters
        inuse = False
        appid = StreamDetails[svID]['appid']
        for key in streamFilter:
            if StreamDetails[key]['appid'] == appid:
                inuse = True
        if inuse == False:
            if lib61850.SVReceiver_isRunning(receiver) == True:
                lib61850.SVReceiver_stop(receiver)

            lib61850.SVReceiver_removeSubscriber(receiver, subscribers[appid])

            if start == True:
                lib61850.SVReceiver_start(receiver)
                if lib61850.SVReceiver_isRunning(receiver) ==  False:
                    print_to_log("Failed to start SMV subscriber. Reason can be that the Ethernet interface doesn't exist or root permission are required.")
                    sys.exit(-1)
    print_to_log("INFO: SMV %s, %i unsubscribed" % (svID, channel))


def determine_path():
    """Borrowed from wxglade.py"""
    try:
        root = __file__
        if os.path.islink (root):
            root = os.path.realpath (root)
        return os.path.dirname (os.path.abspath (root))
    except:
        print("ERROR: __file__ variable missing")
        sys.exit ()
        

def start ():
    global receiver
    global streamListingThread
    global networkInfo
    path = determine_path()
    print( "path:" + path )
    print("Data files path:")

    files = [f for f in os.listdir(path + "/templates")]
    print("\n" + path + "/templates")
    print(files)

    print("\n" + path + "/static")
    files = [f for f in os.listdir(path + "/static")]
    print(files)
    print("\n")


    receiver = lib61850.SVReceiver_create()

    interface_name = _get_interface_name()
    if len(sys.argv) > 1:
        print_to_log("Set interface id: %s" % interface_name)
    else:
        print_to_log("Using interface eth0")
    lib61850.SVReceiver_setInterfaceId(receiver, interface_name)
    networkInfo = _read_network_info(interface_name)

    # general stream listener thread to catch all streams(subscribed and unsubscribed)
    streamListingThread = threading.Thread(target=getSMVStreams, args=(interface_name,-1))
    streamListingThread.start()
    #subs = subscribe(receiver, None, None, "simpleIOGenericIO/LLN0$GO$gcbAnalogValues",str(1))

    application.run(host="0.0.0.0", debug=False, threaded=True) # debug=true will start 2 subscriber threads

    lib61850.SVReceiver_stop(receiver)
    lib61850.SVReceiver_destroy(receiver)


if __name__ == "__main__":
    start()
