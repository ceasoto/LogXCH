import pandas as pd
import re
import streamlit as st
import os

CONNECTOR_STATES = {
    1: "Available",
    2: "Self-checking",
    3: "ERROR",
    5: "Charging",
    6: "Billing",
    7: "Delaying info",
    8: "Delaying",
    9: "Waiting to be plugged in",
    10: "Self-checking fail",
    11: "Emergency stop",
    13: "Unavailable",
    20: "Under reservation"
}

byte2_codes = {
    0x0: "CCS_Stop_Code_None",
    0x1: "CCS_Stop_Code_APP",
    0x2: "CCS_Stop_Code_hardware_alarm",
    0x3: "CCS_Stop_Code_Plug_out",
    0x4: "CCS_Stop_Code_ReadyToCharge_Performance_Time_out",
    0x5: "CCS_Stop_Code_Comm_Error",
    0x6: "CCS_Stop_Code_Comm_EV_ResponseCode",
    0x7: "CCS_Stop_Code_Comm_EV_SessionStop",
    0x8: "CCS_Stop_Code_EVSEIsolationStatus_Fail",
    0x9: "CCS_Stop_Code_EVTargetVoltage_Fail",
    0x10: "CCS_Stop_Code_EVTargetCurrent_Fail",
    0x11: "CCS_Stop_Code_EVSEPresentVoltage_Fail",
    0x12: "CCS_Stop_Code_EVSEPresentCurrent_Fail",
    0x13: "CCS_Stop_Code_CP_Fail",
    0x14: "CCS_Stop_Code_EVSE_Batter_Polarity_Fail",
    0x15: "CCS_Stop_Code_EVSE_Charge_Befor_Overvoltage_Fail",
    0x16: "CCS_Stop_Code_EVSE_insulation_after_Overvoltage",
    0x17: "CCS_Stop_Code_EVSE_Undervoltage",
    0x18: "CCS_Stop_Code_Ongoing_Performance_Timeout"
}

byte3_codes = {
    0x1: "START_charger",
    0x2: "OVER_charger",
    0x3: "BMS_TIMEOUT1",
    0x4: "BMS_TIMEOUT2",
    0x5: "Meter_abnormal1",
    0x6: "Meter_abnormal2",
    0x7: "Power_moudel_abnormal",
    0x8: "Iso_moudel_abnormal1",
    0x9: "Iso_moudel_abnormal2",
    0x10: "JERK_TRIGGER",
    0x11: "LIQUID_LEVEL",
    0x12: "TEMPERATURE_ALARM",
    0x13: "ANTI_THUNDER_AC",
    0x14: "ANTI_THUNDER_DC1",
    0x15: "ANTI_THUNDER_DC2",
    0x16: "TEMPERATURE_GUN1_ALARM",
    0x17: "TEMPERATURE_GUN2_ALARM",
    0x18: "AC_A_INPUT_ALARM",
    0x19: "AC_B_INPUT_ALARM",
    0x20: "AC_C_INPUT_ALARM",
    0x21: "FRONTT_DOOR_ALARM",
    0x22: "BACK_DOOR_ALARM",
    0x23: "RCD_DIN_ALARM",
    0x24: "ANGLE_ALARM",
    0x25: "FLOW1_ALARM",
    0x26: "FLOW2_ALARM",
    0x31: "A8_HEARTBEAT_TIME_OUT"
}

byte4_codes = {
    0x0: "V2G_OK",
    0x1: "V2G_OK_NewSessionEstablished",
    0x2: "V2G_OK_OldSessionJoined",
    0x3: "V2G_OK_CertificateExpiresSoon",
    0x4: "V2G_FAILED",
    0x5: "V2G_FAILED_SequenceError",
    0x6: "V2G_FAILED_ServiceIDInvalid",
    0x7: "V2G_FAILED_UnknownSession",
    0x8: "V2G_FAILED_ServiceSelectionInvalid",
    0x9: "V2G_FAILED_PaymentSelectionInvalid",
    0x10: "V2G_FAILED_CertificateExpired",
    0x11: "V2G_FAILED_SignatureError",
    0x12: "V2G_FAILED_NoCertificateAvailable",
    0x13: "V2G_FAILED_CertChainError",
    0x14: "V2G_FAILED_ChallengeInvalid",
    0x15: "V2G_FAILED_ContractCanceled",
    0x16: "V2G_FAILED_WrongChargeParameter",
    0x17: "V2G_FAILED_PowerDeliveryNotApplied",
    0x18: "V2G_FAILED_TariffSelectionInvalid",
    0x19: "V2G_FAILED_ChargingProfileInvalid",
    0x20: "V2G_FAILED_EVSEPresentVoltageToLow",
    0x21: "V2G_FAILED_MeteringSignatureNotValid",
    0x22: "V2G_FAILED_WrongEnergyTransferType"
}

byte5_codes = {
    0x0: "V2G_NO_ERROR",
    0x1: "V2G_INIT_ERROR_QCA7000",
    0x2: "V2G_INIT_ERROR_OTHER",
    0x10: "V2G_INIT_ERROR_GENERAL",
    0x11: "V2G_INIT_ERROR_IFADDR",
    0x12: "V2G_INIT_ERROR_THREAD",
    0x13: "V2G_INIT_ERROR_OPENCHANNEL",
    0x14: "V2G_INIT_ERROR_KEY",
    0x20: "V2G_SLAC_ERROR_GENERAL",
    0x21: "V2G_SLAC_ERROR_TIMER_INIT",
    0x22: "V2G_SLAC_ERROR_TIMER_TIMEOUT",
    0x23: "V2G_SLAC_ERROR_TIMER_MISC",
    0x24: "V2G_SLAC_ERROR_PARAM_TIMEOUT",
    0x25: "V2G_SLAC_ERROR_PARAM_SOCKET",
    0x26: "V2G_SLAC_ERROR_START_ATTEN_CHAR_TIMEOUT",
    0x27: "V2G_SLAC_ERROR_MNBC_SOUND_TIMEOUT",
    0x28: "V2G_SLAC_ERROR_ATTEN_CHAR_TIMEOUT",
    0x29: "V2G_SLAC_ERROR_ATTEN_CHAR_SOCKET",
    0x2a: "V2G_SLAC_ERROR_VALIDATE_1_TIMEOUT",
    0x2b: "V2G_SLAC_ERROR_VALIDATE_1_SOCKET",
    0x2c: "V2G_SLAC_ERROR_VALIDATE_2_TIMEOUT",
    0x2d: "V2G_SLAC_ERROR_VALIDATE_2_SOCKET",
    0x2e: "V2G_SLAC_ERROR_BCB_TOGGLE_TIMEOUT",
    0x2f: "V2G_SLAC_ERROR_MATCH_TIMEOUT",
    0x30: "V2G_SLAC_ERROR_MATCH_SOCKET",
    0x31: "V2G_SLAC_ERROR_READ_SOCKET",
    0x32: "V2G_SLAC_ERROR_SET_KEY",
    0x33: "V2G_SLAC_ERROR_LINK_TIMEOUT",
    0x40: "V2G_SDP_ERROR_GENERAL",
    0x41: "V2G_SDP_ERROR_INIT_SOCKET",
    0x42: "V2G_SDP_ERROR_INIT_SOCKOPT1",
    0x43: "V2G_SDP_ERROR_INIT_SOCKOPT2",
    0x44: "V2G_SDP_ERROR_INIT_BIND",
    0x45: "V2G_SDP_ERROR_THREAD_SOCKET1",
    0x46: "V2G_SDP_ERROR_THREAD_SOCKET2",
    0x47: "V2G_SDP_ERROR_TIMEOUT",
    0x48: "V2G_SDP_ERROR_TCP_DISCONNECTED",
    0x50: "V2G_DIN_ERROR_GENERAL",
    0x51: "V2G_DIN_ERROR_INIT_SOCKET",
    0x52: "V2G_DIN_ERROR_INIT_SOCKOPT",
    0x53: "V2G_DIN_ERROR_INIT_BIND",
    0x54: "V2G_DIN_ERROR_INIT_LISTEN",
    0x55: "V2G_DIN_ERROR_INIT_SELECT",
    0x56: "V2G_DIN_ERROR_INIT_ACCEPT",
    0x57: "V2G_DIN_ERROR_TIMEOUT",
    0x58: "V2G_DIN_ERROR_V2GTP_HEADER",
    0x59: "V2G_DIN_ERROR_V2GTP_HEADER_LEN",
    0x5a: "V2G_DIN_ERROR_DECODE_EXI",
    0x5b: "V2G_DIN_ERROR_CREATE_RESPONSE",
    0x5c: "V2G_DIN_ERROR_ENCODE_EXI",
    0x5d: "V2G_DIN_ERROR_V2GTP_HEADER_WRITE",
    0x5e: "V2G_DIN_ERROR_SOCKET_EXCEPTION",
    0x5f: "V2G_DIN_ERROR_SOCKET_SEND",
    0x60: "V2G_DIN_ERROR_NO_PROTOCOL"
}

# Extraer líneas con DCB y decodificar
def process_dcb_logs(log_lines):
    dcb_data = []
    for line in log_lines:
        # Extraer timestamp como caracteres del 2 al 20
        extracted_chars = line[1:20] if len(line) >= 20 else line[1:]
        timestamp = extracted_chars if extracted_chars else "Unknown Timestamp"
        
        # Buscar "812d" en la línea
        match_dcb = re.search(r'812d>>>>(.*)', line)
        if match_dcb:
            dcb_code = match_dcb.group(1).strip()  # Extraer todo el contenido después de "812d>>>>"
            match_bytes = re.findall(r'0x[0-9A-Fa-f]+', dcb_code)
            if len(match_bytes) == 6:
                byte0 = int(match_bytes[0], 16)
                byte1 = int(match_bytes[1], 16)
                byte2 = int(match_bytes[2], 16)
                byte3 = int(match_bytes[3], 16)
                byte4 = int(match_bytes[4], 16)
                byte5 = int(match_bytes[5], 16)
                
                dcb_data.append({
                    'Timestamp': timestamp,
                    '812d': f"812d>>>>{dcb_code}",  # Incluir la línea completa analizada
                    'Connector': byte0,
                    'CCS Standard': byte1,
                    'Stop Reason': byte2_codes.get(byte2, f"Unknown (0x{byte2:X})"),
                    'EVSE Error': byte3_codes.get(byte3, f"Unknown (0x{byte3:X})"),
                    'EV Error Msg': byte4_codes.get(byte4, f"Unknown (0x{byte4:X})"),
                    'EV Error Code': byte5_codes.get(byte5, f"Unknown (0x{byte5:X})")
                })
    
    return pd.DataFrame(dcb_data)


# Cargar archivo de códigos de error automáticamente con dirección relativa
def load_error_codes():
    # Obtener el directorio del script actual
    script_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(script_dir, "C6_Error.xlsx")
    
    # Verificar si el archivo existe
    if not os.path.exists(file_path):
        st.error(f"Error code file '{file_path}' not found in the current directory.")
        return None
    
    # Cargar todas las hojas desde el archivo Excel
    xls = pd.ExcelFile(file_path)
    error_dataframes = []
    
    for sheet_name in xls.sheet_names:
        # Leer cada hoja desde la celda B2
        df = xls.parse(sheet_name, skiprows=1)
        
        # Eliminar la primera columna
        df = df.iloc[:, 1:]  # Seleccionar todas las columnas excepto la primera
        
        # Verificar si la columna 'XCharge Error Code' existe antes de eliminar NaN
        if 'XCharge Error Code' in df.columns:
            df = df.dropna(subset=['XCharge Error Code'])  # Eliminar filas con NaN en 'XCharge Error Code'
        
        # Añadir DataFrame procesado a la lista
        error_dataframes.append(df)
    
    # Concatenar todos los DataFrames en uno solo
    if error_dataframes:
        return pd.concat(error_dataframes, ignore_index=True)
    else:
        st.error("No valid data found in the Excel file.")
        return None


# Extraer temperatura y otros datos del log
def extract_temperature_data(log_lines):
    temp_data = []
    
    for line in log_lines:
        # Extraer el timestamp como caracteres del 2 al 20
        extracted_chars = line[1:20] if len(line) >= 20 else line[1:]
        
        # Extraer temperatura
        match_temp = re.search(r'\[tem:(\d+)\]', line)
        temperature = int(match_temp.group(1)) if match_temp else None
        
        if temperature is not None:
            temp_data.append({
                'Timestamp': extracted_chars,  # Timestamp como caracteres extraídos
                'Temperature': temperature
            })
    
    return pd.DataFrame(temp_data)


# Analizar el log y buscar códigos de error
def analyze_log(log_lines, error_codes):
    log_results = []
    error_codes_from_dict = error_codes['XCharge Error Code'].dropna().unique()
    
    for line in log_lines:
        # Extraer los caracteres del 2 al 20
        extracted_chars = line[1:20] if len(line) >= 20 else line[1:]
        timestamp = extracted_chars if extracted_chars else "Unknown Timestamp"
        
        for code in error_codes_from_dict:
            if code in line:  # Comprobar si el código de error del diccionario está en la línea del log
                # Obtener la descripción del código de error desde el diccionario
                description_row = error_codes[error_codes['XCharge Error Code'] == code]
                description = description_row['Description.1'].values[0] if not description_row.empty else "No description found"
                
                # Añadir el resultado
                log_results.append({
                    'Date & Time': timestamp,
                    'Error Code': code,
                    'Description': description
                })
    
    return pd.DataFrame(log_results)


# Extraer cambios de estado de conectores
def extract_connector_states(log_lines):
    connector_data = []
    prev_c1_state, prev_c2_state = None, None
    
    for line in log_lines:
        # Extraer el timestamp como caracteres del 2 al 20
        extracted_chars = line[1:20] if len(line) >= 20 else line[1:]
        
        # Extraer estados de los conectores
        match = re.search(r'\[C1:(\d+)-C2:(\d+)\]', line)
        if match:
            c1_state = int(match.group(1))
            c2_state = int(match.group(2))
            
            # Registrar cambios de estado para C1
            if c1_state != prev_c1_state:
                connector_data.append({
                    'Timestamp': extracted_chars,
                    'Connector': 'C1',
                    'State': CONNECTOR_STATES.get(c1_state, f"Unknown ({c1_state})"),
                    'Value': c1_state  # Agregar el valor de C1
                })
                prev_c1_state = c1_state
            
            # Registrar cambios de estado para C2
            if c2_state != prev_c2_state:
                connector_data.append({
                    'Timestamp': extracted_chars,
                    'Connector': 'C2',
                    'State': CONNECTOR_STATES.get(c2_state, f"Unknown ({c2_state})"),
                    'Value': c2_state  # Agregar el valor de C2
                })
                prev_c2_state = c2_state
    
    return pd.DataFrame(connector_data)



# Streamlit interfaz
st.title("Log Analyzer and Temperature Plot")
st.write("Upload a log file to analyze logs for errors and extract temperature data.")

# Cargar códigos de error automáticamente
error_codes = load_error_codes()
if error_codes is not None:
    st.write("Error Codes Loaded:")
    st.dataframe(error_codes)
    
    log_files = st.file_uploader("Upload Log Files", type=["txt"], accept_multiple_files=True)
    
    if log_files:
        # Leer las líneas del archivo de log
        log_lines = log_file.readlines()
        log_lines = [line.decode("utf-8") for line in log_lines]  # Decodificar las líneas del archivo
        
        # Extraer datos de temperatura
        temperature_data = extract_temperature_data(log_lines)
        
        # Analizar el log
        log_data = analyze_log(log_lines, error_codes)

        # Extraer cambios de estado de conectores
        connector_states = extract_connector_states(log_lines)

        # Procesar DCB logs
        dcb_results = process_dcb_logs(log_lines)

        
        if not log_data.empty:
            st.write("Error Results:")
            st.dataframe(log_data)
            st.download_button(
                label="Download Results as CSV",
                data=log_data.to_csv(index=False),
                file_name="log_analysis_results.csv",
                mime="text/csv"
            )
        
        # Graficar los datos de temperatura
        if not temperature_data.empty:
            st.write("Temperature Data:")
            st.dataframe(temperature_data)
            st.line_chart(temperature_data.set_index('Timestamp'))
        else:
            st.write("No temperature data found.")
        # Mostrar cambios de estado de conectores
        if not connector_states.empty:
            st.write("Connector State Changes:")
            st.dataframe(connector_states)
            st.download_button(
                label="Download Connector State Changes as CSV",
                data=connector_states.to_csv(index=False),
                file_name="connector_state_changes.csv",
                mime="text/csv"
            )
        else:
            st.write("No connector state changes found.")      
        # Mostrar resultados de DCB
        if not dcb_results.empty:
            st.write("DCB Results:")
            st.dataframe(dcb_results)
            st.download_button(
                label="Download DCB Results as CSV",
                data=dcb_results.to_csv(index=False),
                file_name="dcb_results.csv",
                mime="text/csv"
            )
        else:
            st.write("No DCB data found.")  
else:
    st.stop()
