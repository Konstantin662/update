#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DDoS Protection Monitor - Расширенная версия с полнофункциональным GUI
Мониторинг трафика, выявление и предотвращение DDoS-атак
Включает Telegram бот и улучшенные алгоритмы анализа
"""
import sys
import threading
import time
from datetime import datetime, timedelta
from collections import defaultdict, deque
import json
import os
import platform
import subprocess
import queue
import statistics
from typing import Dict, List, Tuple, Optional, Any
import logging
try:
    import tkinter as tk
    from tkinter import ttk, messagebox, scrolledtext
    import scapy.all as scapy
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    import psutil
    import requests
    import numpy as np # Not actively used, but kept for potential future complex analysis
    from threading import Thread, Lock
except ImportError as e:
    print(f"Ошибка импорта: {e}")
    print("Установите необходимые пакеты: pip install scapy psutil requests numpy tk") # Added tk for explicitness
    sys.exit(1)

# Настройка логирования
os.makedirs('logs', exist_ok=True) # Moved up for early creation
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/ddos_monitor.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class TelegramBotAdvanced:
    """Расширенный Telegram бот для управления DDoS монитором"""
    
    def __init__(self, token: str, authorized_users: list, 
                 firewall_manager=None, sniffer=None, analyzer=None):
        self.token = token
        self.authorized_users = set(authorized_users) if authorized_users else set()
        self.base_url = f"https://api.telegram.org/bot{token}" if token else None
        self.firewall_manager = firewall_manager
        self.sniffer = sniffer
        self.analyzer = analyzer # DDoS Analyzer instance
        
        self.is_running = False
        self.last_update_id = 0
        self.enabled = bool(token and authorized_users)
        
        self.commands = {
            '/start': self.cmd_start,
            '/help': self.cmd_help,
            '/stats': self.cmd_stats,
            '/status': self.cmd_status,
            '/block_ip': self.cmd_block_ip,
            '/unblock_ip': self.cmd_unblock_ip,
            '/block_port': self.cmd_block_port,
            '/unblock_port': self.cmd_unblock_port,
            '/list_blocked': self.cmd_list_blocked,
            '/alerts': self.cmd_recent_alerts,
            '/threshold': self.cmd_set_threshold,
            '/stop_bot': self.cmd_stop_bot
        }
        
        self.recent_alerts = deque(maxlen=50) # Use deque for efficient max_alerts
        self.alert_cooldown = {}
        self.cooldown_period = 300
        
    def start_bot(self):
        if not self.enabled:
            logger.info("Telegram бот отключен - нет токена или авторизованных пользователей.")
            return None
            
        self.is_running = True
        logger.info("Telegram bot запущен")
        bot_thread = threading.Thread(target=self._bot_loop, daemon=True)
        bot_thread.start()
        return bot_thread
    
    def stop_bot(self):
        self.is_running = False
        logger.info("Telegram bot остановлен")
    
    def _bot_loop(self):
        while self.is_running:
            try:
                updates = self._get_updates()
                for update in updates:
                    self._process_update(update)
                time.sleep(1)
            except requests.exceptions.RequestException as e:
                logger.warning(f"Ошибка сети в цикле бота (getUpdates): {e}")
                time.sleep(10) # Longer sleep on network issues
            except Exception as e:
                logger.error(f"Ошибка в цикле бота: {e}", exc_info=True)
                time.sleep(5)
    
    def _get_updates(self) -> list:
        # No change needed here unless specific errors occur
        try:
            url = f"{self.base_url}/getUpdates"
            params = {
                'offset': self.last_update_id + 1,
                'timeout': 10,
                'limit': 100
            }
            
            response = requests.get(url, params=params, timeout=15)
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            data = response.json()
            if data['ok'] and data['result']:
                self.last_update_id = data['result'][-1]['update_id']
                return data['result']
            return []
        except requests.exceptions.Timeout:
            logger.warning("Timeout при получении обновлений от Telegram.")
            return []
        except requests.exceptions.ConnectionError:
            logger.warning("Ошибка соединения при получении обновлений от Telegram.")
            return []
        except Exception as e:
            logger.error(f"Ошибка получения обновлений: {e}")
            return []

    def _process_update(self, update: dict):
        # No change needed here
        try:
            if 'message' in update:
                message = update['message']
                chat_id = message['chat']['id']
                user_id = message['from']['id']
                text = message.get('text', '').strip()
                
                if user_id not in self.authorized_users:
                    self._send_message(chat_id, "❌ У вас нет прав для использования этого бота")
                    return
                
                if text.startswith('/'):
                    command_parts = text.split(' ', 1)
                    command = command_parts[0].lower()
                    args_str = command_parts[1] if len(command_parts) > 1 else ""
                    
                    if command in self.commands:
                        self.commands[command](chat_id, args_str)
                    else:
                        self._send_message(chat_id, f"❌ Неизвестная команда: {command}")
        except Exception as e:
            logger.error(f"Ошибка обработки обновления: {e}", exc_info=True)

    def _send_message(self, chat_id: int, text: str, parse_mode: str = None) -> bool:
        # No change needed here unless specific errors occur
        if not self.base_url: return False
        try:
            url = f"{self.base_url}/sendMessage"
            data = {'chat_id': chat_id, 'text': text[:4096], 'parse_mode': parse_mode} # Max 4096 chars
            response = requests.post(url, data=data, timeout=10)
            if response.status_code == 200:
                return True
            else:
                logger.warning(f"Telegram API sendMessage failed: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            logger.error(f"Ошибка отправки сообщения: {e}")
            return False
            
    def send_alert(self, alert: dict) -> bool:
        if not self.enabled:
            return False
        try:
            alert_key = f"{alert['type']}_{alert.get('source_ip', 'unknown')}"
            current_time = time.time()
            
            if alert_key in self.alert_cooldown and \
               current_time - self.alert_cooldown[alert_key] < self.cooldown_period:
                return False 
            
            self.alert_cooldown[alert_key] = current_time
            self.recent_alerts.append(alert) # Already a deque
            
            severity_emoji = {'Low': '🟡', 'Medium': '🟠', 'High': '🔴', 'Critical': '⚫'}.get(alert.get('severity', 'Medium'), '⚪')
            
            message = f"""
{severity_emoji} <b>DDoS ALERT</b> {severity_emoji}
<b>Тип атаки:</b> {alert['type']}
<b>IP источник:</b> <code>{alert.get('source_ip', 'N/A')}</code>
<b>Уровень:</b> {alert.get('severity', 'Medium')}
<b>Время:</b> {alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}
<b>Пакетов/Rate:</b> {alert.get('count', 'N/A')} {alert.get('rate_info', '')}
<b>Направление:</b> {alert.get('direction', 'N/A')}
<b>Описание:</b> {alert.get('description', 'Не указано')}
Используйте команды:
/block_ip {alert.get('source_ip', '')} - для блокировки
/stats - для просмотра статистики
"""
            success_all = True
            for user_id in self.authorized_users:
                if not self._send_message(user_id, message, 'HTML'):
                    success_all = False
            return success_all
        except Exception as e:
            logger.error(f"Ошибка отправки алерта: {e}", exc_info=True)
            return False

    def cmd_start(self, chat_id: int, args: str):
        message = """
🛡️ <b>DDoS Protection Monitor Bot v2.1</b>
Система защиты от DDoS-атак с улучшенными алгоритмами.
<b>Ключевые особенности:</b>
• Улучшенная детекция SYN/UDP Flood
• Фильтр входящего/исходящего трафика
• Адаптивные пороги детекции (в разработке)
• Автоматическая блокировка
<b>Доступные команды:</b>
/help - Помощь по командам
/stats - Статистика трафика
/status - Статус системы
/block_ip <IP> - Заблокировать IP
/alerts - Последние алерты
🔹 <b>Статус:</b> <b>Активен</b>
"""
        self._send_message(chat_id, message, 'HTML')
    
    def cmd_help(self, chat_id: int, args: str):
        message = """
📖 <b>Справка по командам</b>
<b>Мониторинг:</b>
/stats - Статистика трафика
/status - Статус системы мониторинга
/alerts - Последние 5 алертов
<b>Блокировка:</b>
/block_ip 192.168.1.100 - Заблокировать IP
/unblock_ip 192.168.1.100 - Разблокировать IP
/block_port 80 [tcp|udp] - Заблокировать порт (протокол опционально, по умолчанию tcp)
/unblock_port 80 [tcp|udp] - Разблокировать порт
/list_blocked - Список заблокированных
<b>Настройки:</b>
/threshold syn_flood 200 - Установить порог SYN flood (пакетов/минуту)
/threshold udp_flood 500 - Установить порог UDP flood (пакетов/минуту)
💡 <b>Улучшения v2.1:</b>
• Более точная детекция флуд-атак
• Стабильная работа мониторинга
• Завершенные команды управления
"""
        self._send_message(chat_id, message, 'HTML')

    def cmd_stats(self, chat_id: int, args: str):
        try:
            if self.sniffer and self.firewall_manager:
                stats = self.sniffer.get_stats() # Sniffer specific stats
                blocked_ips_count = len(self.firewall_manager.blocked_ips)
                blocked_ports_count = len(self.firewall_manager.blocked_ports)
                
                message = f"""
📊 <b>Статистика трафика v2.1</b>
📈 <b>Пакеты (обработано сниффером):</b>
• Всего: {stats['total_packets']:,}
• TCP: {stats['tcp_packets']:,}
• UDP: {stats['udp_packets']:,}
• ICMP: {stats['icmp_packets']:,}
🔄 <b>По направлению (относительно локальных IP):</b>
• Входящих: {stats.get('incoming_packets', 0):,}
• Исходящих: {stats.get('outgoing_packets', 0):,}
🌐 <b>Адреса:</b>
• Уникальных IP (в сессии): {stats['unique_ips']:,}
🛡️ <b>Блокировки (активные в Firewall):</b>
• Заблокировано IP: {blocked_ips_count}
• Заблокировано портов: {blocked_ports_count}
🎯 <b>Детекция (Анализатор):</b>
• SYN Flood обнаружено: {self.analyzer.detection_stats['syn_flood_detected'] if self.analyzer else 'N/A'}
• UDP Flood обнаружено: {self.analyzer.detection_stats['udp_flood_detected'] if self.analyzer else 'N/A'}
⏰ <b>Обновлено:</b> {datetime.now().strftime('%H:%M:%S')}
"""
            else:
                message = "❌ Сервис мониторинга или FirewallManager недоступен"
            
            self._send_message(chat_id, message, 'HTML')
            
        except Exception as e:
            logger.error(f"Ошибка получения статистики для Telegram: {e}", exc_info=True)
            self._send_message(chat_id, "❌ Ошибка получения статистики")

    def cmd_status(self, chat_id: int, args: str):
        # ... (similar to original, check self.sniffer.is_running, self.is_running)
        # Add analyzer status if relevant
        try:
            monitoring_status = "🟢 Активен" if self.sniffer and self.sniffer.is_running else "🔴 Неактивен"
            bot_status = "🟢 Активен" if self.is_running else "🔴 Неактивен"
            analyzer_status = "🟢 Активен" if self.analyzer else "🔴 Недоступен"
            
            message = f"""
🔍 <b>Статус системы v2.1</b>
🖥️ <b>Мониторинг трафика:</b> {monitoring_status}
🤖 <b>Telegram бот:</b> {bot_status}
🕵️ <b>Анализатор DDoS:</b> {analyzer_status}
🛡️ <b>Межсетевой экран:</b> {'🟢 Доступен' if self.firewall_manager else '🔴 Недоступен'}
📡 <b>Интерфейс:</b> {getattr(self.sniffer, 'selected_interface', 'Не выбран')}
📊 <b>Алертов сохранено:</b> {len(self.recent_alerts)}
⏰ <b>Время проверки:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
            self._send_message(chat_id, message, 'HTML')
        except Exception as e:
            logger.error(f"Ошибка получения статуса для Telegram: {e}", exc_info=True)
            self._send_message(chat_id, "❌ Ошибка получения статуса системы")
    
    def cmd_block_ip(self, chat_id: int, args: str):
        ip_to_block = args.strip()
        if not ip_to_block:
            self._send_message(chat_id, "❌ Укажите IP-адрес. Пример: /block_ip 1.2.3.4")
            return
        if self.firewall_manager:
            success, msg = self.firewall_manager.block_ip(ip_to_block)
            response = f"✅ {msg}" if success else f"❌ {msg}"
            self._send_message(chat_id, response)
            if success: logger.info(f"IP {ip_to_block} заблокирован через Telegram пользователем {chat_id}")
        else:
            self._send_message(chat_id, "❌ Менеджер межсетевого экрана недоступен.")

    def cmd_unblock_ip(self, chat_id: int, args: str):
        ip_to_unblock = args.strip()
        if not ip_to_unblock:
            self._send_message(chat_id, "❌ Укажите IP-адрес. Пример: /unblock_ip 1.2.3.4")
            return
        if self.firewall_manager:
            success, msg = self.firewall_manager.unblock_ip(ip_to_unblock)
            response = f"✅ {msg}" if success else f"❌ {msg}"
            self._send_message(chat_id, response)
            if success: logger.info(f"IP {ip_to_unblock} разблокирован через Telegram пользователем {chat_id}")
        else:
            self._send_message(chat_id, "❌ Менеджер межсетевого экрана недоступен.")

    def cmd_list_blocked(self, chat_id: int, args: str):
        # ... (original logic is fine, ensure self.firewall_manager is checked)
        if not self.firewall_manager:
            self._send_message(chat_id, "❌ Менеджер межсетевого экрана недоступен.")
            return
        
        blocked_ips = list(self.firewall_manager.blocked_ips)
        blocked_ports = list(self.firewall_manager.blocked_ports)
        
        message = "🛡️ <b>Список заблокированных</b>\n\n"
        
        if blocked_ips:
            message += "<b>Заблокированные IP (последние 20):</b>\n"
            message += "\n".join([f"• <code>{ip}</code>" for ip in blocked_ips[-20:]])
            if len(blocked_ips) > 20: message += f"\n... и еще {len(blocked_ips) - 20}"
        else:
            message += "<b>Заблокированные IP:</b> Нет\n"
        
        message += "\n\n"
        
        if blocked_ports:
            message += "<b>Заблокированные порты (последние 10):</b>\n"
            message += "\n".join([f"• <code>{port}</code>" for port in blocked_ports[-10:]])
            if len(blocked_ports) > 10: message += f"\n... и еще {len(blocked_ports) - 10}"
        else:
            message += "<b>Заблокированные порты:</b> Нет\n"
            
        self._send_message(chat_id, message, 'HTML')

    def cmd_recent_alerts(self, chat_id: int, args: str):
        # ... (original logic is fine using self.recent_alerts deque)
        if not self.recent_alerts:
            self._send_message(chat_id, "📭 Нет недавних алертов.")
            return
        
        message = "🚨 <b>Последние 5 алертов</b>\n\n"
        # Iterate in reverse if you want newest first, but deque stores oldest at left.
        # To show newest 5, take last 5 items.
        alerts_to_show = list(self.recent_alerts)[-5:] 
        for alert in reversed(alerts_to_show): # Show newest first from the selection
            severity_emoji = {'Low': '🟡', 'Medium': '🟠', 'High': '🔴', 'Critical': '⚫'}.get(alert.get('severity', 'Medium'), '⚪')
            message += f"{severity_emoji} <b>{alert['type']}</b> от <code>{alert.get('source_ip', 'N/A')}</code>\n"
            message += f"<b>Уровень:</b> {alert.get('severity', 'Medium')}\n"
            message += f"<b>Время:</b> {alert['timestamp'].strftime('%H:%M:%S')}\n"
            message += f"<b>Инфо:</b> {alert.get('description', '')}\n"
            message += f"{'-'*25}\n"
            
        self._send_message(chat_id, message, 'HTML')

    def cmd_block_port(self, chat_id: int, args: str):
        parts = args.strip().split()
        if not parts:
            self._send_message(chat_id, "❌ Укажите порт и опционально протокол (tcp/udp). Пример: /block_port 80 tcp")
            return
        
        try:
            port = int(parts[0])
            protocol = 'tcp' # Default
            if len(parts) > 1 and parts[1].lower() in ['tcp', 'udp']:
                protocol = parts[1].lower()
            elif len(parts) > 1:
                self._send_message(chat_id, f"❌ Неверный протокол: {parts[1]}. Используйте 'tcp' или 'udp'.")
                return

            if not (0 < port < 65536):
                self._send_message(chat_id, "❌ Неверный номер порта (0-65535).")
                return

            if self.firewall_manager:
                success, msg = self.firewall_manager.block_port(port, protocol)
                response = f"✅ {msg}" if success else f"❌ {msg}"
                self._send_message(chat_id, response)
                if success: logger.info(f"Порт {port}/{protocol} заблокирован через Telegram пользователем {chat_id}")
            else:
                self._send_message(chat_id, "❌ Менеджер межсетевого экрана недоступен.")
        except ValueError:
            self._send_message(chat_id, "❌ Неверный формат порта. Укажите число.")
        except Exception as e:
            logger.error(f"Ошибка block_port в Telegram: {e}", exc_info=True)
            self._send_message(chat_id, f"❌ Ошибка: {str(e)}")

    def cmd_unblock_port(self, chat_id: int, args: str):
        parts = args.strip().split()
        if not parts:
            self._send_message(chat_id, "❌ Укажите порт и опционально протокол (tcp/udp). Пример: /unblock_port 80 tcp")
            return
        
        try:
            port = int(parts[0])
            protocol = 'tcp' # Default
            if len(parts) > 1 and parts[1].lower() in ['tcp', 'udp']:
                protocol = parts[1].lower()
            elif len(parts) > 1:
                self._send_message(chat_id, f"❌ Неверный протокол: {parts[1]}. Используйте 'tcp' или 'udp'.")
                return

            if not (0 < port < 65536):
                self._send_message(chat_id, "❌ Неверный номер порта (0-65535).")
                return

            if self.firewall_manager:
                success, msg = self.firewall_manager.unblock_port(port, protocol)
                response = f"✅ {msg}" if success else f"❌ {msg}"
                self._send_message(chat_id, response)
                if success: logger.info(f"Порт {port}/{protocol} разблокирован через Telegram пользователем {chat_id}")
            else:
                self._send_message(chat_id, "❌ Менеджер межсетевого экрана недоступен.")
        except ValueError:
            self._send_message(chat_id, "❌ Неверный формат порта. Укажите число.")
        except Exception as e:
            logger.error(f"Ошибка unblock_port в Telegram: {e}", exc_info=True)
            self._send_message(chat_id, f"❌ Ошибка: {str(e)}")

    def cmd_set_threshold(self, chat_id: int, args: str):
        parts = args.strip().split()
        if len(parts) != 2:
            self._send_message(chat_id, "❌ Укажите тип атаки и значение. Пример: /threshold syn_flood 200")
            return

        attack_type_input = parts[0].lower()
        try:
            value_ppm = int(parts[1]) # Value from user is in Packets Per Minute (PPM)
            if value_ppm <= 0:
                self._send_message(chat_id, "❌ Значение порога должно быть положительным.")
                return

            if not self.analyzer:
                self._send_message(chat_id, "❌ Анализатор DDoS недоступен.")
                return

            # Convert PPM to PPS for internal use
            value_pps = value_ppm / 60.0 
            
            threshold_key_map = {
                'syn_flood': 'syn_flood',
                'syn': 'syn_flood',
                'udp_flood': 'udp_flood',
                'udp': 'udp_flood',
                'tcp_flood': 'tcp_flood', # Example, if you have tcp_flood
                'tcp': 'tcp_flood'
            }

            if attack_type_input not in threshold_key_map:
                self._send_message(chat_id, f"❌ Неизвестный тип атаки для порога: {attack_type_input}. Доступно: syn_flood, udp_flood.")
                return
            
            threshold_key = threshold_key_map[attack_type_input]

            if threshold_key in self.analyzer.thresholds:
                self.analyzer.thresholds[threshold_key] = value_pps
                self._send_message(chat_id, f"✅ Порог для {threshold_key} установлен на {value_ppm} пакетов/минуту ({value_pps:.2f} pkt/s).")
                logger.info(f"Порог {threshold_key} изменен на {value_ppm} PPM ({value_pps:.2f} PPS) через Telegram пользователем {chat_id}")
            else:
                self._send_message(chat_id, f"❌ Внутренняя ошибка: ключ порога {threshold_key} не найден в анализаторе.")

        except ValueError:
            self._send_message(chat_id, "❌ Неверное значение порога. Укажите число.")
        except Exception as e:
            logger.error(f"Ошибка set_threshold в Telegram: {e}", exc_info=True)
            self._send_message(chat_id, f"❌ Ошибка установки порога: {str(e)}")
    
    def cmd_stop_bot(self, chat_id: int, args: str):
        self._send_message(chat_id, "🛑 Бот останавливается...")
        self.stop_bot()

class ImprovedDDoSAnalyzer:
    def __init__(self, config: Dict[str, Any], alert_callback=None):
        self.config = config
        self.detection_config = config.get('detection', {})
        self.alert_callback = alert_callback
        
        self.baseline_duration_seconds = self.detection_config.get('baseline_duration_seconds', 300) # 5 minutes
        self.analysis_window_seconds = self.detection_config.get('analysis_window_seconds', 60) # Window for current metrics, not used for flood detection window
        self.DETECTION_WINDOW_SECONDS = self.detection_config.get('flood_detection_window_seconds', 10) # Detect flood over this period

        # For adaptive thresholds - overall traffic baseline (packets per second)
        self.traffic_baseline = {
            'syn_packets': deque(maxlen=self.baseline_duration_seconds), # Stores {'timestamp': ..., 'count': pps}
            'udp_packets': deque(maxlen=self.baseline_duration_seconds), # Stores {'timestamp': ..., 'count': pps}
        }
        self.temp_syn_count_current_second = 0
        self.temp_udp_count_current_second = 0
        self.baseline_update_lock = Lock()
        self.baseline_timer_thread = None # To control the timer thread
        self._schedule_baseline_update()

        # For flood detection - per-IP packet timestamps
        self.ip_syn_packet_timestamps = defaultdict(lambda: deque(maxlen=20000)) # Max packets to track per IP in window to prevent memory exhaustion
        self.ip_udp_packet_timestamps = defaultdict(lambda: deque(maxlen=20000))

        self.whitelist = set(self.config.get('whitelist_ips', [
            '8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '208.67.222.222', '208.67.220.220',
        ]))
        
        self.local_ips = self._get_local_ips()
        
        self.detection_stats = defaultdict(int) # More flexible
        
        # Thresholds are now stored internally as Packets Per Second (PPS)
        # Conversion from config (PPM) happens in DDoSMonitorGUI or TelegramBot
        # Default base thresholds in PPS (e.g., 200 PPM = 3.33 PPS)
        self.thresholds = {
            'syn_flood': self.detection_config.get('syn_flood', {}).get('base_threshold_pps', 200/60.0),
            'udp_flood': self.detection_config.get('udp_flood', {}).get('base_threshold_pps', 500/60.0),
            # 'tcp_flood': 300/60.0 # If you add other types
        }
        
        self.lock = Lock() # General purpose lock if needed for other shared states
        
        logger.info("ImprovedDDoSAnalyzer инициализирован. Flood detection window: %ss", self.DETECTION_WINDOW_SECONDS)
        logger.info(f"Локальные IP адреса: {self.local_ips}")

    def _get_local_ips(self) -> set:
        local_ips = set(['127.0.0.1', '::1']) # Add loopback by default
        try:
            for _, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET: # IPv4
                        local_ips.add(addr.address)
                    # elif addr.family == socket.AF_INET6: # IPv6 if needed
                    #    local_ips.add(addr.address)
        except Exception as e:
            logger.warning(f"Не удалось получить локальные IP: {e}")
        return local_ips

    def _schedule_baseline_update(self):
        if self.baseline_timer_thread and self.baseline_timer_thread.is_alive():
             self.baseline_timer_thread.cancel() # Cancel previous if any (should not happen with daemon)

        # Use a stoppable thread for cleaner shutdown if analyzer has a stop method
        def timer_loop():
            while getattr(threading.current_thread(), "do_run", True):
                time.sleep(1.0)
                self._update_baseline_metrics()
            logger.info("Baseline update loop stopped.")

        self.baseline_timer_thread = threading.Thread(target=timer_loop, daemon=True)
        self.baseline_timer_thread.do_run = True # Signal to run
        self.baseline_timer_thread.start()
        logger.info("Baseline metrics update task scheduled every 1 second.")
        
    def _update_baseline_metrics(self):
        with self.baseline_update_lock:
            current_time = time.time()
            self.traffic_baseline['syn_packets'].append({
                'timestamp': current_time,
                'count': self.temp_syn_count_current_second
            })
            self.traffic_baseline['udp_packets'].append({
                'timestamp': current_time,
                'count': self.temp_udp_count_current_second
            })
            self.temp_syn_count_current_second = 0
            self.temp_udp_count_current_second = 0
        # logger.debug(f"Baseline updated: SYN baseline size {len(self.traffic_baseline['syn_packets'])}, UDP baseline size {len(self.traffic_baseline['udp_packets'])}")


    def stop_analyzer(self):
        if self.baseline_timer_thread:
            logger.info("Stopping baseline update loop...")
            self.baseline_timer_thread.do_run = False # Signal thread to stop
            self.baseline_timer_thread.join(timeout=2.0) # Wait for it to finish

    def classify_traffic_direction(self, src_ip: str, dst_ip: str) -> str:
        if src_ip in self.local_ips: return "outgoing"
        if dst_ip in self.local_ips: return "incoming"
        return "transit"
    
    def is_whitelisted(self, ip: str) -> bool:
        return ip in self.whitelist
    
    def calculate_adaptive_threshold(self, metric_name: str, base_threshold_pps: float) -> float:
        baseline_data = self.traffic_baseline.get(metric_name)
        print(str(base_threshold_pps))
        if not baseline_data or len(baseline_data) < self.detection_config.get('min_baseline_samples', 10):
            return base_threshold_pps


        recent_time_cutoff = time.time() - self.analysis_window_seconds
        recent_pps_values = [item['count'] for item in baseline_data if item['timestamp'] > recent_time_cutoff]

        if not recent_pps_values or len(recent_pps_values) < self.detection_config.get('min_recent_samples', 10):
            return base_threshold_pps

        mean_pps = statistics.mean(recent_pps_values)
        std_dev_pps = statistics.stdev(recent_pps_values) if len(recent_pps_values) > 1 else 0

        # Adaptive threshold: mean + X * std_dev (X based on sensitivity)
        sensitivity_multiplier = {'low': 3.0, 'medium': 2.5, 'high': 2.0}.get(
            self.detection_config.get('sensitivity', 'medium'), 2.5)
        
        adaptive_pps = mean_pps + (sensitivity_multiplier * std_dev_pps)
        print(str(statistics.mean(recent_pps_values)) +" " + str(sensitivity_multiplier) + " " + str(std_dev_pps) + str(adaptive_pps))
        print(str(adaptive_pps))

        return max(adaptive_pps, base_threshold_pps)

    def analyze_packet(self, packet_info):
        try:
            src_ip = packet_info['src_ip']
            dst_ip = packet_info['dst_ip']
            
            direction = self.classify_traffic_direction(src_ip, dst_ip)
            packet_info['direction'] = direction # Add to packet_info for later use/display
            
            if self.is_whitelisted(src_ip) and direction == "incoming": # Whitelist only for incoming
                return

            with self.lock: # Use self.lock if other parts of analyze_packet modify shared state
                self.detection_stats['total_packets_analyzed'] += 1
            
            if packet_info['protocol'] == 'TCP' and 'flags' in packet_info and (packet_info['flags'] & 0x02):  # SYN
                with self.baseline_update_lock: # For temp counters
                    self.temp_syn_count_current_second += 1
                self._check_syn_flood_advanced(src_ip, packet_info)
            
            elif packet_info['protocol'] == 'UDP':
                with self.baseline_update_lock: # For temp counters
                    self.temp_udp_count_current_second += 1
                self._check_udp_flood_advanced(src_ip, packet_info)
        except Exception as e:
            logger.error(f"Ошибка анализа пакета ({packet_info.get('src_ip')}->{packet_info.get('dst_ip')}): {e}", exc_info=True)

    def _check_syn_flood_advanced(self, ip, packet_info):
        current_time = time.time()
        timestamps = self.ip_syn_packet_timestamps[ip]
        timestamps.append(current_time)

        # Prune old timestamps (deque maxlen helps, but explicit prune is safer for varying rates)
        while timestamps and timestamps[0] < current_time - self.DETECTION_WINDOW_SECONDS:
            timestamps.popleft()
        
        count_in_window = len(timestamps)
        current_rate_pps = count_in_window / self.DETECTION_WINDOW_SECONDS
        print("SYN IRL - " + str(current_rate_pps))
        # Use adaptive threshold (which falls back to static if baseline is not ready)
        # self.thresholds['syn_flood'] is already in PPS
        adaptive_threshold_pps = self.calculate_adaptive_threshold('syn_packets', self.thresholds['syn_flood'])
        print("SYN THRESH - " + str(adaptive_threshold_pps))
        # Attack if incoming, not whitelisted, and rate exceeds adaptive threshold
        if (packet_info.get('direction') == 'incoming' and
            not self.is_whitelisted(ip) and 
            current_rate_pps > adaptive_threshold_pps):
            
            alert = {
                'timestamp': datetime.now(),
                'type': 'SYN Flood',
                'source_ip': ip,
                'severity': 'High', # Could be dynamic based on how much threshold is exceeded
                'count': count_in_window, # Packets in window
                'rate_info': f"{current_rate_pps:.1f} pkt/s over {self.DETECTION_WINDOW_SECONDS}s",
                'direction': packet_info.get('direction', 'unknown'),
                'description': f'SYN Flood с IP {ip} ({current_rate_pps:.1f} pkt/s, порог {adaptive_threshold_pps:.1f} pkt/s)',
                'used_threshold_pps': adaptive_threshold_pps
            }
            self._trigger_alert(alert)
            with self.lock: # Use self.lock for detection_stats
                self.detection_stats['syn_flood_detected'] += 1

    def _check_udp_flood_advanced(self, ip, packet_info):
        current_time = time.time()
        timestamps = self.ip_udp_packet_timestamps[ip]
        timestamps.append(current_time)

        while timestamps and timestamps[0] < current_time - self.DETECTION_WINDOW_SECONDS:
            timestamps.popleft()
        
        count_in_window = len(timestamps)
        current_rate_pps = count_in_window / self.DETECTION_WINDOW_SECONDS
        print("UDP IRL - " + str(current_rate_pps))
        adaptive_threshold_pps = self.calculate_adaptive_threshold('udp_packets', self.thresholds['udp_flood'])
        print("UDP THRESH - " + str(adaptive_threshold_pps))
        if (packet_info.get('direction') == 'incoming' and
            not self.is_whitelisted(ip) and
            current_rate_pps > adaptive_threshold_pps):
            
            alert = {
                'timestamp': datetime.now(),
                'type': 'UDP Flood',
                'source_ip': ip,
                'severity': 'High',
                'count': count_in_window,
                'rate_info': f"{current_rate_pps:.1f} pkt/s over {self.DETECTION_WINDOW_SECONDS}s",
                'direction': packet_info.get('direction', 'unknown'),
                'description': f'UDP Flood с IP {ip} ({current_rate_pps:.1f} pkt/s, порог {adaptive_threshold_pps:.1f} pkt/s)',
                'used_threshold_pps': adaptive_threshold_pps
            }
            self._trigger_alert(alert)
            with self.lock:
                self.detection_stats['udp_flood_detected'] += 1
                
    def _trigger_alert(self, alert):
        logger.warning(f"ALERT: {alert['type']} от {alert['source_ip']} ({alert.get('description', '')})")
        if self.alert_callback:
            try:
                self.alert_callback(alert)
            except Exception as e:
                logger.error(f"Ошибка при вызове alert_callback: {e}", exc_info=True)

# Standard library imports for NetworkSniffer psutil.net_if_addrs and FirewallManager
import socket # For AF_INET

class NetworkSniffer:
    def __init__(self, callback=None):
        self.callback = callback
        self.is_running = False
        self.interfaces = [] # Populated by get_interfaces
        self.selected_interface = None
        self.packet_queue = queue.Queue(maxsize=20000) # Add maxsize to prevent memory bloat if processing is slow
        self.stats = defaultdict(int) # Use defaultdict
        self.stats['unique_ips'] = set() # Override for set
        self.stats_lock = Lock()
        self.local_ips = self._get_local_ips()
        
    def _get_local_ips(self) -> set:
        local_ips = set(['127.0.0.1', '::1'])
        try:
            for _, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        local_ips.add(addr.address)
        except Exception as e:
            logger.warning(f"Sniffer: Не удалось получить локальные IP: {e}")
        return local_ips
    
    def _classify_traffic_direction(self, src_ip: str, dst_ip: str) -> str:
        if src_ip in self.local_ips: return "outgoing"
        if dst_ip in self.local_ips: return "incoming"
        return "transit"
        
    def get_interfaces(self):
        # Original logic seems fine, ensure scapy.arch.get_if_list() for non-Windows if scapy.get_if_list() deprecated
        try:
            if platform.system() == "Windows":
                # Use psutil.net_if_addrs() keys which are interface names
                self.interfaces = list(psutil.net_if_addrs().keys())
                # Or filter for IPv4 capable as before:
                # interfaces = []
                # for interface, addrs in psutil.net_if_addrs().items():
                #     if any(addr.family == socket.AF_INET for addr in addrs):
                #         interfaces.append(interface)
                # self.interfaces = interfaces

            else: # Linux, macOS
                # scapy.get_if_list() can be problematic, try psutil here too for consistency
                # self.interfaces = [iface.name for iface in scapy.get_working_interfaces()]
                # Or fallback to psutil universally if scapy method is unreliable
                self.interfaces = list(psutil.net_if_addrs().keys())

            # Filter out loopback unless explicitly needed, and ensure they are usable strings
            self.interfaces = [str(i) for i in self.interfaces if i and 'lo' not in str(i).lower()]

        except Exception as e:
            logger.error(f"Ошибка получения интерфейсов: {e}", exc_info=True)
            self.interfaces = ['eth0', 'en0', 'wlan0'] # Common fallbacks
        return self.interfaces

    def packet_handler(self, packet):
        try:
            if IP not in packet: return

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            direction = self._classify_traffic_direction(src_ip, dst_ip)
            
            # Update basic stats (thread-safe due to GIL on dict updates, but lock for complex ops)
            with self.stats_lock:
                self.stats['total_packets'] += 1
                self.stats['unique_ips'].add(src_ip)
                self.stats['unique_ips'].add(dst_ip) # Count both src and dst for unique IPs encountered
                if direction == 'incoming': self.stats['incoming_packets'] += 1
                elif direction == 'outgoing': self.stats['outgoing_packets'] += 1
            
            packet_info = {
                'timestamp': datetime.now(), 'src_ip': src_ip, 'dst_ip': dst_ip,
                'protocol': 'IP', 'size': len(packet), 'direction': direction
            }
            
            if TCP in packet:
                with self.stats_lock: self.stats['tcp_packets'] += 1
                packet_info.update({'protocol': 'TCP', 'src_port': packet[TCP].sport, 
                                    'dst_port': packet[TCP].dport, 'flags': packet[TCP].flags})
            elif UDP in packet:
                with self.stats_lock: self.stats['udp_packets'] += 1
                packet_info.update({'protocol': 'UDP', 'src_port': packet[UDP].sport, 'dst_port': packet[UDP].dport})
            elif ICMP in packet:
                with self.stats_lock: self.stats['icmp_packets'] += 1
                packet_info.update({'protocol': 'ICMP', 'icmp_type': packet[ICMP].type, 'icmp_code': packet[ICMP].code})
            
            # Put to queue for analyzer/GUI (non-blocking if queue has space)
            try:
                self.packet_queue.put_nowait(packet_info)
            except queue.Full:
                logger.warning("Packet queue full, dropping packet. Analysis might be lagging.")
                with self.stats_lock: self.stats['dropped_from_queue'] +=1


            # Direct callback (e.g., to GUI for live display if needed, but queue is better)
            # If callback is used, ensure it's fast or also uses a queue
            if self.callback: # This callback is DDoSMonitorGUI.on_packet_received
                self.callback(packet_info) # This needs to be fast. It puts to self.analyzer and self.packets_data.
                                            # Analyzer runs in same thread if called directly.
                                            # It's better if on_packet_received just queues for analyzer.
                                            # For now, existing structure is kept.
                    
        except Exception as e:
            logger.error(f"Ошибка обработки пакета (scapy): {e}", exc_info=True)

    def start_sniffing(self, interface=None, filter_expr="ip"): # Filter "ip" to get only IP packets
        if not interface:
            logger.error("Не выбран интерфейс для захвата.")
            return
        self.is_running = True
        self.selected_interface = interface

        try:
            logger.info(f"Запуск захвата на интерфейсе: {interface}, фильтр: '{filter_expr}'")
            scapy.sniff(
                iface=interface,
                prn=self.packet_handler,
                filter=filter_expr,
                store=False, # Do not store packets in memory by sniff itself
                stop_filter=lambda p: not self.is_running # Check flag to stop
            )
            logger.info(f"Захват на интерфейсе {interface} остановлен.")
        except PermissionError:
             logger.error(f"Ошибка прав доступа для захвата на {interface}. Запустите с правами администратора/root.")
             messagebox.showerror("Ошибка прав", f"Необходимы права администратора/root для захвата с интерфейса {interface}.")
             self.is_running = False # Ensure state is correct
        except OSError as e: # Handle Scapy/libpcap errors like "No such device"
            logger.error(f"Ошибка захвата пакетов (OSError) на {interface}: {e}")
            if "No such device" in str(e) or "Network is down" in str(e):
                 messagebox.showerror("Ошибка интерфейса", f"Интерфейс {interface} не найден или неактивен. Попробуйте другой.")
            else:
                 messagebox.showerror("Ошибка захвата", f"Произошла ошибка при запуске захвата на {interface}: {e}")
            self.is_running = False
        except Exception as e:
            logger.error(f"Критическая ошибка захвата пакетов на {interface}: {e}", exc_info=True)
            self.is_running = False
    
    def stop_sniffing(self):
        self.is_running = False # Signal sniff to stop
    
    def get_stats(self):
        with self.stats_lock:
            # Return a copy to avoid issues if defaultdict tries to create keys outside lock
            current_stats = dict(self.stats) 
            current_stats['unique_ips'] = len(self.stats['unique_ips']) # Convert set to count
            return current_stats

class FirewallManager:
    def __init__(self):
        self.system = platform.system()
        self.blocked_ips = set()
        self.blocked_ports = set() # Stores "port/protocol" strings e.g. "80/tcp"
    
    def _run_command(self, cmd_parts: List[str]) -> Tuple[bool, str]:
        """Helper to run firewall commands."""
        try:
            # For Linux, 'sudo' is often needed. Ensure it's prefixed if so.
            # For Windows, script should already be admin.
            if self.system == "Linux" and cmd_parts[0] != "sudo":
                if os.geteuid() == 0: # Already root
                    pass
                else: # Needs sudo
                    # This is tricky. 'sudo iptables ...' requires passwordless sudo setup
                    # or the script to be run as root. check_admin_rights handles this.
                    # Assuming script is root or passwordless sudo for iptables is configured.
                    # For simplicity, we assume 'sudo' is handled by how the script is run.
                    # cmd_parts.insert(0, "sudo") # This can be problematic
                    pass


            # Use subprocess.run with timeout
            # Shell=True is a security risk if ip/port can be crafted. Avoid if possible.
            # Here, ip/port are somewhat controlled.
            full_cmd_str = " ".join(cmd_parts)
            logger.info(f"Executing firewall command: {full_cmd_str}")
            result = subprocess.run(full_cmd_str, shell=True, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                return True, "Команда выполнена успешно."
            else:
                # Log full error for debugging
                error_msg = result.stderr.strip() if result.stderr else result.stdout.strip()
                logger.error(f"Ошибка выполнения команды '{full_cmd_str}': RC={result.returncode}, Error: {error_msg}")
                return False, f"Ошибка: {error_msg}"
        except subprocess.TimeoutExpired:
            logger.error(f"Таймаут при выполнении команды: {full_cmd_str}")
            return False, "Таймаут выполнения команды."
        except Exception as e:
            logger.error(f"Исключение при выполнении команды '{full_cmd_str}': {e}", exc_info=True)
            return False, f"Исключение: {str(e)}"

    def block_ip(self, ip: str):
        if not ip or not isinstance(ip, str): return False, "Неверный IP-адрес."
        # Basic IP validation could be added here.
        if ip in self.blocked_ips: return True, f"IP {ip} уже заблокирован."

        cmd_parts = []
        if self.system == "Linux":
            cmd_parts = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        elif self.system == "Windows":
            rule_name = f"DDoS_Block_IP_{ip.replace('.', '_')}" # Sanitize rule name
            cmd_parts = ["netsh", "advfirewall", "firewall", "add", "rule", 
                         f'name="{rule_name}"', "dir=in", "action=block", f"remoteip={ip}"]
        else:
            return False, "Неподдерживаемая ОС для управления Firewall."

        success, msg = self._run_command(cmd_parts)
        if success:
            self.blocked_ips.add(ip)
            return True, f"IP {ip} успешно заблокирован."
        return False, f"Не удалось заблокировать IP {ip}: {msg}"

    def unblock_ip(self, ip: str):
        if not ip or not isinstance(ip, str): return False, "Неверный IP-адрес."
        if ip not in self.blocked_ips and self.system != "Windows": # On Windows, rule might exist even if not in our set
             pass # Allow attempting to remove, might be stale rule
        
        cmd_parts = []
        if self.system == "Linux":
            cmd_parts = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        elif self.system == "Windows":
            rule_name = f"DDoS_Block_IP_{ip.replace('.', '_')}"
            cmd_parts = ["netsh", "advfirewall", "firewall", "delete", "rule", f'name="{rule_name}"']
        else:
            return False, "Неподдерживаемая ОС."

        success, msg = self._run_command(cmd_parts)
        if success:
            self.blocked_ips.discard(ip)
            return True, f"IP {ip} успешно разблокирован."
        # If iptables says "No such rule", it's effectively unblocked.
        if "No such rule" in msg or "No rules match" in msg: # For iptables or netsh
            self.blocked_ips.discard(ip)
            return True, f"IP {ip} не найден в правилах (считается разблокированным)."
        return False, f"Не удалось разблокировать IP {ip}: {msg}"

    def block_port(self, port: int, protocol: str = 'tcp'):
        port_proto_key = f"{port}/{protocol.lower()}"
        if port_proto_key in self.blocked_ports: return True, f"Порт {port_proto_key} уже заблокирован."
        
        cmd_parts = []
        if self.system == "Linux":
            cmd_parts = ["iptables", "-A", "INPUT", "-p", protocol.lower(), f"--dport", str(port), "-j", "DROP"]
        elif self.system == "Windows":
            rule_name = f"DDoS_Block_Port_{protocol}_{port}"
            cmd_parts = ["netsh", "advfirewall", "firewall", "add", "rule",
                         f'name="{rule_name}"', "dir=in", "action=block", 
                         f"protocol={protocol.lower()}", f"localport={port}"]
        else:
            return False, "Неподдерживаемая ОС."
            
        success, msg = self._run_command(cmd_parts)
        if success:
            self.blocked_ports.add(port_proto_key)
            return True, f"Порт {port_proto_key} успешно заблокирован."
        return False, f"Не удалось заблокировать порт {port_proto_key}: {msg}"

    def unblock_port(self, port: int, protocol: str = 'tcp'):
        port_proto_key = f"{port}/{protocol.lower()}"
        # if port_proto_key not in self.blocked_ports and self.system != "Windows":
        #     pass # Allow attempt to remove

        cmd_parts = []
        if self.system == "Linux":
            cmd_parts = ["iptables", "-D", "INPUT", "-p", protocol.lower(), f"--dport", str(port), "-j", "DROP"]
        elif self.system == "Windows":
            rule_name = f"DDoS_Block_Port_{protocol}_{port}"
            cmd_parts = ["netsh", "advfirewall", "firewall", "delete", "rule", f'name="{rule_name}"']
        else:
            return False, "Неподдерживаемая ОС."
            
        success, msg = self._run_command(cmd_parts)
        if success:
            self.blocked_ports.discard(port_proto_key)
            return True, f"Порт {port_proto_key} успешно разблокирован."
        if "No such rule" in msg or "No rules match" in msg:
            self.blocked_ports.discard(port_proto_key)
            return True, f"Порт {port_proto_key} не найден в правилах (считается разблокированным)."
        return False, f"Не удалось разблокировать порт {port_proto_key}: {msg}"

class DDoSMonitorGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("DDoS Protection Monitor v2.1 - Улучшенный интерфейс")
        self.root.geometry("1400x900")
        
        self.setup_variables()
        config = self.load_config()
        
        # Components
        self.firewall = FirewallManager() # Firewall first, as other components might use it implicitly
        self.sniffer = NetworkSniffer(callback=self.on_packet_received_from_sniffer) # Renamed callback
        self.analyzer = ImprovedDDoSAnalyzer(config, alert_callback=self.on_alert_received_from_analyzer) # Renamed
        
        telegram_config = config.get('telegram', {})
        self.telegram_bot = TelegramBotAdvanced(
            token=telegram_config.get('bot_token', ''),
            authorized_users=telegram_config.get('authorized_users', []),
            firewall_manager=self.firewall,
            sniffer=self.sniffer,
            analyzer=self.analyzer
        )
        self.telegram_bot.start_bot()
        
        # Load thresholds (PPM from config, convert to PPS for analyzer)
        # Store original PPM for display in GUI config tab
        ddos_thresholds_config = config.get('ddos_thresholds', {})
        self.gui_thresholds_ppm = { # For display
            'syn_flood': ddos_thresholds_config.get('syn_flood_threshold', 200),
            'udp_flood': ddos_thresholds_config.get('udp_flood_threshold', 500),
            # 'tcp_flood': ddos_thresholds_config.get('tcp_flood_threshold', 300),
        }
        self.analyzer.thresholds['syn_flood'] = self.gui_thresholds_ppm['syn_flood'] / 60.0
        self.analyzer.thresholds['udp_flood'] = self.gui_thresholds_ppm['udp_flood'] / 60.0
        # self.analyzer.thresholds['tcp_flood'] = self.gui_thresholds_ppm['tcp_flood'] / 60.0

        self.packets_display_buffer = deque(maxlen=1000) # For GUI display, updated from sniffer queue
        self.alerts_data = deque(maxlen=200) # For GUI display
        self.is_monitoring = False
        self.sniffer_thread = None
        self.gui_packet_processor_thread = None # Thread to process packets from sniffer's queue for GUI
        
        self.create_widgets()
        self.update_stats_display_job_id = None # For tk.after job
        self.start_stats_updater() # Start the recurring GUI stats update

        # Start a thread to process packets from sniffer's queue for GUI and analyzer
        self._start_gui_packet_processor()

    def _start_gui_packet_processor(self):
        self.gui_packet_processor_active = True
        self.gui_packet_processor_thread = threading.Thread(target=self._process_sniffer_queue, daemon=True)
        self.gui_packet_processor_thread.start()

    def _stop_gui_packet_processor(self):
        self.gui_packet_processor_active = False
        if self.gui_packet_processor_thread and self.gui_packet_processor_thread.is_alive():
            self.gui_packet_processor_thread.join(timeout=1.0)

    def _process_sniffer_queue(self):
        """Dedicated thread to pull packets from sniffer.packet_queue and send to analyzer & GUI buffer."""
        logger.info("GUI Packet Processor thread started.")
        while self.gui_packet_processor_active:
            try:
                packet_info = self.sniffer.packet_queue.get(timeout=0.5) # Timeout to allow checking active flag
                
                # Send to analyzer (analyzer itself is mostly thread-safe with locks)
                if self.analyzer:
                    self.analyzer.analyze_packet(packet_info) 
                
                # Add to GUI display buffer (deque is thread-safe for append/pop)
                self.packets_display_buffer.append(packet_info)

                # Schedule GUI update for packets table (throttled if needed)
                # For simplicity, let a periodic updater handle table refresh from packets_display_buffer
                # Or schedule directly: self.root.after(0, self.update_packets_display)
                # Let's use a periodic update via update_stats_display for packets table as well.

            except queue.Empty:
                continue # No packet, loop again
            except Exception as e:
                logger.error(f"Error in GUI packet processor: {e}", exc_info=True)
        logger.info("GUI Packet Processor thread stopped.")


    def setup_variables(self):
        self.traffic_filter = tk.StringVar(value="all")
        self.protocol_var = tk.StringVar(value="Все")
        self.ip_filter_var = tk.StringVar()
        self.interface_var = tk.StringVar()
        self.block_ip_var = tk.StringVar()
        # For config tab thresholds (these will hold PPM values for display)
        self.syn_threshold_ppm_var = tk.StringVar()
        self.udp_threshold_ppm_var = tk.StringVar()

    def load_config(self):
        try:
            with open('config.json', 'r', encoding='utf-8') as f: config = json.load(f)
            logger.info("Конфигурация config.json загружена.")
            return config
        except FileNotFoundError:
            logger.warning("Файл config.json не найден, используются значения по умолчанию.")
        except Exception as e:
            logger.error(f"Ошибка загрузки конфигурации: {e}", exc_info=True)
        # Default config structure if load fails
        return {
            'detection': {
                'baseline_duration_seconds': 300, 'analysis_window_seconds': 60,
                'flood_detection_window_seconds': 10, 'min_baseline_samples': 30,
                'min_recent_samples': 10, 'sensitivity': 'medium',
                'syn_flood': {'base_threshold_pps': 200/60.0}, # Default to PPS here if analyzer expects it
                'udp_flood': {'base_threshold_pps': 500/60.0}
            },
            'telegram': {'bot_token': '', 'authorized_users': []},
            'ddos_thresholds': { # These are PPM for user convenience
                'syn_flood_threshold': 200, 'udp_flood_threshold': 500, 
                # 'tcp_flood_threshold': 300 
            },
            'whitelist_ips': ['8.8.8.8', '1.1.1.1']
        }

    def create_widgets(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.create_monitoring_tab()
        self.create_alerts_tab()
        self.create_config_tab() # Call after self.gui_thresholds_ppm is set
        
        self.status_frame = ttk.Frame(self.root)
        self.status_frame.pack(fill=tk.X, padx=10, pady=5)
        self.status_label = ttk.Label(self.status_frame, text="DDoS Protection Monitor v2.1 - Готов")
        self.status_label.pack(side=tk.LEFT)
        self.status_indicator = ttk.Label(self.status_frame, text="●", foreground='red', font=('Arial', 12))
        self.status_indicator.pack(side=tk.RIGHT, padx=10)

    def create_monitoring_tab(self):
        # ... (largely unchanged, ensure Treeview setup is robust)
        self.monitor_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.monitor_frame, text="Мониторинг трафика")
        
        control_frame = ttk.LabelFrame(self.monitor_frame, text="Управление")
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        control_row1 = ttk.Frame(control_frame)
        control_row1.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(control_row1, text="Интерфейс:").pack(side=tk.LEFT, padx=5)
        self.interface_combo = ttk.Combobox(control_row1, textvariable=self.interface_var, width=20, state="readonly")
        self.interface_combo.pack(side=tk.LEFT, padx=5)
        self.refresh_interfaces() # Populate combobox
        
        self.start_button = ttk.Button(control_row1, text="▶ Запуск", command=self.start_monitoring)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(control_row1, text="⏹ Стоп", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        traffic_filter_frame = ttk.LabelFrame(self.monitor_frame, text="Фильтр направления трафика v2.1")
        traffic_filter_frame.pack(fill=tk.X, padx=5, pady=5)
        filter_row = ttk.Frame(traffic_filter_frame)
        filter_row.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(filter_row, text="Направление:", font=('Arial', 10, 'bold')).pack(side=tk.LEFT, padx=5)
        radio_frame = ttk.Frame(filter_row)
        radio_frame.pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(radio_frame, text="🌐 Весь трафик", variable=self.traffic_filter, value="all", command=self.on_traffic_filter_change).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(radio_frame, text="⬇️ Входящий", variable=self.traffic_filter, value="incoming", command=self.on_traffic_filter_change).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(radio_frame, text="⬆️ Исходящий", variable=self.traffic_filter, value="outgoing", command=self.on_traffic_filter_change).pack(side=tk.LEFT, padx=5)
        self.filter_status_label = ttk.Label(filter_row, text="Активен: Весь трафик", foreground='blue', font=('Arial', 9, 'bold'))
        self.filter_status_label.pack(side=tk.RIGHT, padx=10)
        
        filter_frame = ttk.LabelFrame(self.monitor_frame, text="Дополнительные фильтры")
        filter_frame.pack(fill=tk.X, padx=5, pady=5)
        filter_controls = ttk.Frame(filter_frame)
        filter_controls.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(filter_controls, text="Протокол:").pack(side=tk.LEFT, padx=5)
        protocol_combo = ttk.Combobox(filter_controls, textvariable=self.protocol_var, values=["Все", "TCP", "UDP", "ICMP"], width=10, state="readonly")
        protocol_combo.current(0)
        protocol_combo.pack(side=tk.LEFT, padx=5)
        ttk.Label(filter_controls, text="IP (содержит):").pack(side=tk.LEFT, padx=5)
        ip_entry = ttk.Entry(filter_controls, textvariable=self.ip_filter_var, width=15)
        ip_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(filter_controls, text="Применить фильтры", command=self.apply_filters).pack(side=tk.LEFT, padx=5)
        
        stats_frame = ttk.LabelFrame(self.monitor_frame, text="Статистика в реальном времени")
        stats_frame.pack(fill=tk.X, padx=5, pady=5)
        self.stats_text_area = scrolledtext.ScrolledText(stats_frame, height=7, width=80, wrap=tk.WORD) # Renamed
        self.stats_text_area.pack(padx=5, pady=5, fill=tk.X)
        
        packets_frame = ttk.LabelFrame(self.monitor_frame, text="Пакеты (с направлением трафика)")
        packets_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        columns = ('Время', 'Направление', 'Источник', 'Назначение', 'Протокол', 'Порт Src', 'Порт Dst', 'Размер')
        self.packets_tree = ttk.Treeview(packets_frame, columns=columns, show='headings', height=15)
        for col in columns:
            self.packets_tree.heading(col, text=col)
            self.packets_tree.column(col, width=100, minwidth=60, stretch=tk.YES) # Adjust widths
        self.packets_tree.column('Время', width=80, stretch=tk.NO)
        self.packets_tree.column('Направление', width=90, stretch=tk.NO)
        self.packets_tree.column('Размер', width=70, stretch=tk.NO)
        packets_scrollbar = ttk.Scrollbar(packets_frame, orient=tk.VERTICAL, command=self.packets_tree.yview)
        self.packets_tree.configure(yscrollcommand=packets_scrollbar.set)
        self.packets_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        packets_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.packets_tree.bind("<Double-1>", self.on_packet_double_click)

    def create_alerts_tab(self):
        # ... (largely unchanged)
        self.alerts_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.alerts_frame, text="Алерты и блокировки")
        
        alert_control_frame = ttk.LabelFrame(self.alerts_frame, text="Управление блокировками")
        alert_control_frame.pack(fill=tk.X, padx=5, pady=5)
        control_row = ttk.Frame(alert_control_frame)
        control_row.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(control_row, text="🗑️ Очистить алерты", command=self.clear_alerts_gui).pack(side=tk.LEFT, padx=5) # Renamed
        ttk.Label(control_row, text="IP для блокировки:").pack(side=tk.LEFT, padx=10)
        ttk.Entry(control_row, textvariable=self.block_ip_var, width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_row, text="🚫 Заблокировать IP", command=self.block_ip_manual).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_row, text="✅ Разблокировать IP", command=self.unblock_ip_manual).pack(side=tk.LEFT, padx=5)
        
        block_stats_frame = ttk.LabelFrame(self.alerts_frame, text="Статистика блокировок")
        block_stats_frame.pack(fill=tk.X, padx=5, pady=5)
        self.block_stats_text_area = scrolledtext.ScrolledText(block_stats_frame, height=4, width=80, wrap=tk.WORD) # Renamed
        self.block_stats_text_area.pack(padx=5, pady=5, fill=tk.X)
        
        alerts_table_frame = ttk.LabelFrame(self.alerts_frame, text="История алертов DDoS (последние 200)")
        alerts_table_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        alert_columns = ('Время', 'Тип атаки', 'IP источник', 'Направление', 'Уровень', 'Инфо', 'Описание')
        self.alerts_tree = ttk.Treeview(alerts_table_frame, columns=alert_columns, show='headings', height=20)
        for col in alert_columns:
            self.alerts_tree.heading(col, text=col)
            self.alerts_tree.column(col, width=120, minwidth=80, stretch=tk.YES)
        self.alerts_tree.column('Время', width=140, stretch=tk.NO)
        self.alerts_tree.column('Описание', width=250) # Wider for description
        alerts_scrollbar = ttk.Scrollbar(alerts_table_frame, orient=tk.VERTICAL, command=self.alerts_tree.yview)
        self.alerts_tree.configure(yscrollcommand=alerts_scrollbar.set)
        self.alerts_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        alerts_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.alert_context_menu = tk.Menu(self.root, tearoff=0)
        self.alert_context_menu.add_command(label="🚫 Заблокировать IP", command=self.block_selected_ip_from_alert) # Renamed
        self.alert_context_menu.add_command(label="📋 Копировать IP", command=self.copy_selected_ip_from_alert) # Renamed
        self.alert_context_menu.add_command(label="📊 Показать детали", command=self.show_alert_details_popup) # Renamed
        self.alerts_tree.bind("<Button-3>", self.show_alert_context_menu) # Right-click

    def create_config_tab(self):
        self.config_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.config_frame, text="Конфигурация")
        
        thresholds_frame = ttk.LabelFrame(self.config_frame, text="Пороги детекции DDoS (пакетов/минуту)")
        thresholds_frame.pack(fill=tk.X, padx=5, pady=5, ipady=5) # Added ipady
        
        # Set StringVar values from loaded PPM thresholds
        self.syn_threshold_ppm_var.set(str(self.gui_thresholds_ppm['syn_flood']))
        self.udp_threshold_ppm_var.set(str(self.gui_thresholds_ppm['udp_flood']))

        syn_frame = ttk.Frame(thresholds_frame)
        syn_frame.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(syn_frame, text="SYN Flood порог (PPM):").pack(side=tk.LEFT, padx=5)
        ttk.Entry(syn_frame, textvariable=self.syn_threshold_ppm_var, width=10).pack(side=tk.LEFT, padx=5)
        
        udp_frame = ttk.Frame(thresholds_frame)
        udp_frame.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(udp_frame, text="UDP Flood порог (PPM):").pack(side=tk.LEFT, padx=5)
        ttk.Entry(udp_frame, textvariable=self.udp_threshold_ppm_var, width=10).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(thresholds_frame, text="Применить пороги", command=self.apply_thresholds_from_gui).pack(pady=10) # Renamed
        
        telegram_frame = ttk.LabelFrame(self.config_frame, text="Настройки Telegram бота")
        telegram_frame.pack(fill=tk.X, padx=5, pady=5, ipady=5)
        bot_info = ttk.Frame(telegram_frame)
        bot_info.pack(fill=tk.X, padx=5, pady=5)
        bot_status = "🟢 Активен" if self.telegram_bot and self.telegram_bot.enabled else "🔴 Отключен"
        ttk.Label(bot_info, text=f"Статус бота: {bot_status}").pack(side=tk.LEFT, padx=5)
        if self.telegram_bot and self.telegram_bot.enabled:
            ttk.Label(bot_info, text=f"Авторизованных пользователей: {len(self.telegram_bot.authorized_users)}").pack(side=tk.LEFT, padx=20)

    def on_traffic_filter_change(self):
        current_filter = self.traffic_filter.get()
        filter_names = {"all": "🌐 Весь трафик", "incoming": "⬇️ Входящий", "outgoing": "⬆️ Исходящий"}
        self.filter_status_label.config(text=f"Активен: {filter_names.get(current_filter, current_filter)}")
        self.apply_filters() # This will re-filter and update display
        logger.info(f"Фильтр направления трафика изменен на: {current_filter}")

    def refresh_interfaces(self):
        interfaces = self.sniffer.get_interfaces()
        self.interface_combo['values'] = interfaces
        if interfaces: self.interface_combo.set(interfaces[0])
        else: self.interface_combo.set("Нет доступных интерфейсов")

    def start_monitoring(self):
        interface = self.interface_var.get()
        if not interface or interface == "Нет доступных интерфейсов":
            messagebox.showerror("Ошибка", "Выберите корректный сетевой интерфейс.")
            return
        
        if self.is_monitoring:
            messagebox.showinfo("Информация", "Мониторинг уже запущен.")
            return

        self.is_monitoring = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_indicator.config(foreground='green')
        
        # Clear old packet data for new session visually
        self.packets_display_buffer.clear() 
        self.update_packets_display() # Clear treeview

        # Start sniffer in its own thread
        self.sniffer_thread = threading.Thread(target=self.sniffer.start_sniffing, args=(interface,"ip"), daemon=True)
        self.sniffer_thread.start()
        
        self.status_label.config(text=f"Мониторинг активен на {interface}")
        logger.info(f"Мониторинг запущен на интерфейсе: {interface}")

    def stop_monitoring(self):
        if not self.is_monitoring: return

        self.is_monitoring = False # Signal sniffer to stop
        if self.sniffer: self.sniffer.stop_sniffing() # This sets sniffer.is_running = False

        if self.sniffer_thread and self.sniffer_thread.is_alive():
            logger.info("Ожидание завершения потока сниффера...")
            self.sniffer_thread.join(timeout=2.0) # Wait for sniff thread to exit
            if self.sniffer_thread.is_alive():
                 logger.warning("Поток сниффера не завершился в таймаут.")
        
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_indicator.config(foreground='red')
        self.status_label.config(text="Мониторинг остановлен")
        logger.info("Мониторинг остановлен.")

    # This is the old direct callback from sniffer. Not used if _process_sniffer_queue is primary.
    # Kept for reference or if a hybrid model is chosen. For now, _process_sniffer_queue is better.
    def on_packet_received_from_sniffer(self, packet_info: Dict):
        """
        DEPRECATED IF _process_sniffer_queue handles this.
        Called directly by sniffer's packet_handler. MUST BE VERY FAST.
        """
        # self.analyzer.analyze_packet(packet_info) # This can be slow
        # self.packets_display_buffer.append(packet_info) 
        # self.root.after(0, self.update_packets_display) # Frequent GUI updates can be slow
        pass


    def on_alert_received_from_analyzer(self, alert: Dict):
        """Callback from ImprovedDDoSAnalyzer when an alert is generated."""
        self.alerts_data.append(alert) # deque is thread-safe for append
        
        # Offload Telegram sending and auto-blocking to a new thread
        # to prevent blocking the analyzer or packet processing pipeline.
        def alert_handling_task():
            logger.debug(f"Alert handling task started for {alert.get('source_ip')}")
            try:
                self.telegram_bot.send_alert(alert)
            
                # Auto-blocking for High/Critical alerts
                if alert.get('severity') in ['High', 'Critical'] and alert.get('source_ip'):
                    logger.info(f"Попытка автоблокировки IP: {alert['source_ip']} из-за алерта типа {alert['type']}")
                    success, message = self.firewall.block_ip(alert['source_ip'])
                    if success:
                        logger.info(f"IP {alert['source_ip']} автоматически заблокирован: {message}")
                        # Update alert description for GUI (careful with shared dict)
                        # It's better to update GUI separately or pass new info
                        # For now, this modification is potentially problematic if dict is reused.
                        # alert['description'] = alert.get('description', '') + f" | Автоблок: {message}"
                    else:
                        logger.warning(f"Автоблокировка IP {alert['source_ip']} не удалась: {message}")
            except Exception as e:
                logger.error(f"Ошибка в потоке обработки алерта: {e}", exc_info=True)
            finally:
                # Schedule GUI updates from this worker thread to the main GUI thread
                self.root.after(0, self.update_alerts_display) # Update alerts table
                self.root.after(0, self.update_block_stats_display) # Update blocking stats text area
                logger.debug(f"Alert handling task finished for {alert.get('source_ip')}")


        threading.Thread(target=alert_handling_task, daemon=True).start()


    def update_packets_display(self):
        """Updates the packets Treeview from self.packets_display_buffer."""
        if not hasattr(self, 'packets_tree') or not self.packets_tree.winfo_exists(): return
        
        # Apply filters to a copy of the buffer for display
        current_display_list = self.apply_packet_filters_for_gui(list(self.packets_display_buffer))

        self.packets_tree.delete(*self.packets_tree.get_children()) # Clear existing items
        
        # Display up to ~100 recent filtered packets to keep GUI responsive
        for packet in current_display_list[-100:]: # Newest at the bottom, so insert at 'end' or reverse and insert at 0
            direction = packet.get('direction', 'unknown')
            dir_symbol = {'incoming': '⬇️', 'outgoing': '⬆️', 'transit': '↔️', 'unknown': '❓'}.get(direction, '❓')
            
            # Ensure all fields exist, provide defaults
            values = (
                packet['timestamp'].strftime('%H:%M:%S.%f')[:-3], # Milliseconds
                f"{dir_symbol} {direction.capitalize()}",
                packet.get('src_ip', '-'), packet.get('dst_ip', '-'),
                packet.get('protocol', '-'), packet.get('src_port', '-'),
                packet.get('dst_port', '-'), packet.get('size', '-')
            )
            self.packets_tree.insert('', 0, values=values) # Insert at top for newest first

    def update_alerts_display(self):
        if not hasattr(self, 'alerts_tree') or not self.alerts_tree.winfo_exists(): return
        self.alerts_tree.delete(*self.alerts_tree.get_children())
        
        # Display recent alerts from self.alerts_data (deque)
        for alert in reversed(list(self.alerts_data)): # Newest first
            direction = alert.get('direction', 'unknown')
            dir_symbol = {'incoming': '⬇️', 'outgoing': '⬆️', 'transit': '↔️', 'unknown': '❓'}.get(direction, '❓')
            
            values = (
                alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                alert.get('type', '-'),
                alert.get('source_ip', '-'),
                f"{dir_symbol} {direction.capitalize()}",
                alert.get('severity', '-'),
                f"{alert.get('count', '-')}{' ' + alert.get('rate_info', '') if alert.get('rate_info') else ''}", # Count and rate
                alert.get('description', '-')
            )
            item_id = self.alerts_tree.insert('', 0, values=values) # Newest at top
            
            # Color coding based on severity
            severity_tag = alert.get('severity', '').lower()
            if severity_tag:
                self.alerts_tree.item(item_id, tags=(severity_tag,))
        
        self.alerts_tree.tag_configure('critical', background='#ff6666', foreground='white')
        self.alerts_tree.tag_configure('high', background='#ffb366')
        self.alerts_tree.tag_configure('medium', background='#ffff99')
        self.alerts_tree.tag_configure('low', background='#cce6ff')

    def update_block_stats_display(self): # Renamed for clarity
        if not hasattr(self, 'block_stats_text_area') or not self.block_stats_text_area.winfo_exists(): return
        try:
            blocked_ips_count = len(self.firewall.blocked_ips)
            blocked_ports_count = len(self.firewall.blocked_ports)
            auto_blocked_count = sum(1 for alert in self.alerts_data if 'Автоблок' in alert.get('description', '')) # Approximation
            
            stats_text = f"""Заблокировано IP: {blocked_ips_count}
Заблокировано портов: {blocked_ports_count}
Обработано алертов (в сессии GUI): {len(self.alerts_data)}
Автоматических блокировок (приблизительно): {auto_blocked_count}
Последнее обновление: {datetime.now().strftime('%H:%M:%S')}"""
            
            self.block_stats_text_area.config(state=tk.NORMAL)
            self.block_stats_text_area.delete(1.0, tk.END)
            self.block_stats_text_area.insert(1.0, stats_text)
            self.block_stats_text_area.config(state=tk.DISABLED)
        except Exception as e:
            logger.error(f"Ошибка обновления статистики блокировок GUI: {e}", exc_info=True)

    def apply_packet_filters_for_gui(self, packets_to_filter: List[Dict]) -> List[Dict]: # Renamed
        """Applies GUI filters to a list of packet dicts."""
        filtered = list(packets_to_filter) # Work on a copy
        
        traffic_f = self.traffic_filter.get()
        if traffic_f != "all":
            filtered = [p for p in filtered if p.get('direction') == traffic_f]
        
        protocol_f = self.protocol_var.get()
        if protocol_f != "Все":
            filtered = [p for p in filtered if p.get('protocol', '').upper() == protocol_f.upper()]
        
        ip_f = self.ip_filter_var.get().strip()
        if ip_f:
            filtered = [p for p in filtered if ip_f in p.get('src_ip', '') or ip_f in p.get('dst_ip', '')]
        
        return filtered
    
    def apply_filters(self):
        # This method is called when filter settings change.
        # It should trigger an update of the packets display.
        self.update_packets_display() 

    def apply_thresholds_from_gui(self): # Renamed
        try:
            syn_ppm = int(self.syn_threshold_ppm_var.get())
            udp_ppm = int(self.udp_threshold_ppm_var.get())

            if syn_ppm <=0 or udp_ppm <=0:
                messagebox.showerror("Ошибка", "Пороги должны быть положительными числами.")
                return

            # Convert PPM from GUI to PPS for analyzer
            self.analyzer.thresholds['syn_flood'] = syn_ppm / 60.0
            self.analyzer.thresholds['udp_flood'] = udp_ppm / 60.0
            
            # Update GUI's storage of PPM values if needed (already in StringVars)
            self.gui_thresholds_ppm['syn_flood'] = syn_ppm
            self.gui_thresholds_ppm['udp_flood'] = udp_ppm

            messagebox.showinfo("Успех", f"Пороги обновлены:\nSYN Flood: {syn_ppm} PPM\nUDP Flood: {udp_ppm} PPM")
            logger.info(f"Пороги обновлены из GUI: SYN={syn_ppm} PPM, UDP={udp_ppm} PPM")
            
        except ValueError:
            messagebox.showerror("Ошибка", "Введите корректные числовые значения для порогов.")
        except Exception as e:
            logger.error(f"Ошибка применения порогов из GUI: {e}", exc_info=True)
            messagebox.showerror("Ошибка", f"Не удалось применить пороги: {e}")

    def clear_alerts_gui(self): # Renamed
        self.alerts_data.clear()
        self.update_alerts_display()
        logger.info("Алерты очищены из GUI.")
    
    # --- Manual Blocking ---
    def block_ip_manual(self):
        ip = self.block_ip_var.get().strip()
        if not ip: messagebox.showerror("Ошибка", "Введите IP-адрес."); return
        success, message = self.firewall.block_ip(ip)
        messagebox.showinfo("Результат блокировки IP", message)
        if success: self.block_ip_var.set(""); self.update_block_stats_display()
    
    def unblock_ip_manual(self):
        ip = self.block_ip_var.get().strip()
        if not ip: messagebox.showerror("Ошибка", "Введите IP-адрес."); return
        success, message = self.firewall.unblock_ip(ip)
        messagebox.showinfo("Результат разблокировки IP", message)
        if success: self.block_ip_var.set(""); self.update_block_stats_display()

    # --- Context Menu Actions for Alerts Tree ---
    def show_alert_context_menu(self, event):
        selection = self.alerts_tree.selection()
        if selection: # Ensure an item is selected
            self.alerts_tree.focus(selection[0]) # Focus on the selected item before showing menu
            self.alert_context_menu.post(event.x_root, event.y_root)
    
    def block_selected_ip_from_alert(self): # Renamed
        selection = self.alerts_tree.selection()
        if not selection: return
        ip_to_block = self.alerts_tree.item(selection[0])['values'][2] # IP is 3rd column
        if ip_to_block and ip_to_block != '-':
            success, message = self.firewall.block_ip(ip_to_block)
            messagebox.showinfo("Блокировка IP из алерта", message)
            if success: self.update_block_stats_display()
        else: messagebox.showwarning("Блокировка IP", "Не удалось извлечь IP из алерта.")
    
    def copy_selected_ip_from_alert(self): # Renamed
        selection = self.alerts_tree.selection()
        if not selection: return
        ip_to_copy = self.alerts_tree.item(selection[0])['values'][2]
        if ip_to_copy and ip_to_copy != '-':
            self.root.clipboard_clear()
            self.root.clipboard_append(ip_to_copy)
            messagebox.showinfo("Копирование IP", f"IP {ip_to_copy} скопирован в буфер обмена.")
        else: messagebox.showwarning("Копирование IP", "Не удалось извлечь IP из алерта.")

    def show_alert_details_popup(self): # Renamed
        selection = self.alerts_tree.selection()
        if not selection: return
        values = self.alerts_tree.item(selection[0])['values']
        details = f"""Детали алерта:
Время: {values[0]}
Тип атаки: {values[1]}
IP источник: {values[2]}
Направление: {values[3]}
Уровень: {values[4]}
Инфо (счетчик/рейт): {values[5]}
Описание: {values[6]}"""
        messagebox.showinfo("Детали алерта", details)

    def on_packet_double_click(self, event):
        selection = self.packets_tree.selection()
        if not selection: return
        values = self.packets_tree.item(selection[0])['values']
        details = f"""Детали пакета:
Время: {values[0]}
Направление: {values[1]}
Источник: {values[2]}
Назначение: {values[3]}
Протокол: {values[4]}
Порт источника: {values[5]}
Порт назначения: {values[6]}
Размер: {values[7]} байт"""
        messagebox.showinfo("Детали пакета", details)
    
    def start_stats_updater(self):
        """Periodically updates GUI elements like stats text area, packet table, alert table."""
        self.update_gui_displays() # Call the consolidated update method
        self.update_stats_display_job_id = self.root.after(2000, self.start_stats_updater) # Reschedule

    def update_gui_displays(self):
        """Consolidated method to refresh various parts of the GUI."""
        if not self.root.winfo_exists(): return # Stop if root window is destroyed

        # Update main stats text area
        if hasattr(self, 'stats_text_area') and self.stats_text_area.winfo_exists():
            sniffer_stats = self.sniffer.get_stats() if self.sniffer else {}
            analyzer_stats = self.analyzer.detection_stats if self.analyzer else {}
            
            text = f"""📊 СТАТИСТИКА ТРАФИКА v2.1 | Фильтр GUI: {self.traffic_filter.get().upper()}
📈 Сниффер ({'Активен' if self.is_monitoring else 'Остановлен'}):
   Всего пакетов: {sniffer_stats.get('total_packets', 0):,} | TCP: {sniffer_stats.get('tcp_packets',0):,} | UDP: {sniffer_stats.get('udp_packets',0):,} | ICMP: {sniffer_stats.get('icmp_packets',0):,}
   Входящих: {sniffer_stats.get('incoming_packets',0):,} | Исходящих: {sniffer_stats.get('outgoing_packets',0):,}
   Уникальных IP (сессия): {sniffer_stats.get('unique_ips',0):,} | Отброшено из очереди: {sniffer_stats.get('dropped_from_queue',0):,}
🎯 Анализатор:
   SYN Flood атак: {analyzer_stats.get('syn_flood_detected',0)} | UDP Flood атак: {analyzer_stats.get('udp_flood_detected',0)}
   Всего пакетов проанализировано: {analyzer_stats.get('total_packets_analyzed',0):,}
🛡️ Firewall:
   Заблокировано IP: {len(self.firewall.blocked_ips)} | Заблокировано портов: {len(self.firewall.blocked_ports)}
⏰ Обновлено: {datetime.now().strftime('%H:%M:%S')}"""
            
            self.stats_text_area.config(state=tk.NORMAL)
            self.stats_text_area.delete(1.0, tk.END)
            self.stats_text_area.insert(1.0, text)
            self.stats_text_area.config(state=tk.DISABLED)

        # Update packets display (from its own buffer, filled by _process_sniffer_queue)
        self.update_packets_display()
        # Alerts display is updated by on_alert_received_from_analyzer via root.after
        # Block stats display is updated by on_alert_received_from_analyzer and manual block actions
        # self.update_block_stats_display() # Can be called here too for regular refresh

    def run(self):
        try:
            self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
            logger.info("DDoS Protection Monitor v2.1 запущен")
            self.root.mainloop()
        except KeyboardInterrupt:
            logger.info("Завершение работы по Ctrl+C")
        finally:
            self.on_closing(from_finally=True) # Ensure cleanup happens

    def on_closing(self, from_finally=False):
        logger.info("DDoS Protection Monitor v2.1 завершает работу...")
        if self.update_stats_display_job_id: # Cancel scheduled GUI updates
            self.root.after_cancel(self.update_stats_display_job_id)
            self.update_stats_display_job_id = None

        if self.is_monitoring: self.stop_monitoring() # Stop sniffer thread
        
        self._stop_gui_packet_processor() # Stop packet processor thread

        if self.analyzer: self.analyzer.stop_analyzer() # Stop analyzer's internal threads (like baseline timer)
        if self.telegram_bot: self.telegram_bot.stop_bot()
            
        if not from_finally: # Avoid destroying root if called from finally block after mainloop error
             if self.root.winfo_exists(): self.root.destroy()
        logger.info("DDoS Protection Monitor завершил работу.")

def check_admin_rights() -> bool: # Added return type hint
    try:
        if platform.system() == "Windows":
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                # No messagebox here, main will handle it if GUI is attempted
                logger.error("Требуются права администратора Windows.")
                return False
        elif platform.system() in ["Linux", "Darwin"]: # macOS is Darwin
            if os.geteuid() != 0:
                logger.error("Требуются права суперпользователя (root) для Linux/macOS.")
                return False
        return True
    except Exception as e:
        logger.warning(f"Не удалось проверить права администратора: {e}")
        return False # Safer to assume no rights if check fails

def main():
    print("🛡️ DDoS Protection Monitor v2.1 - Расширенный интерфейс")
    print("=" * 70)
    
    has_admin_rights = check_admin_rights()

    if not has_admin_rights:
        # For GUI apps, it's better to show a tkinter messagebox if tkinter is available
        try:
            root_check = tk.Tk()
            root_check.withdraw() # Hide the empty root window
            messagebox.showerror("Ошибка прав доступа",
                                 "Для захвата сетевых пакетов и управления firewall "
                                 "необходимы права администратора (Windows) или суперпользователя (Linux/macOS).\n\n"
                                 "Пожалуйста, перезапустите приложение с соответствующими правами.")
            root_check.destroy()
        except tk.TclError: # If display is not available (e.g. server environment)
             print("ОШИБКА: Для захвата сетевых пакетов и управления firewall "
                  "необходимы права администратора (Windows) или суперпользователя (Linux/macOS).")
        sys.exit(1)
    
    try:
        app = DDoSMonitorGUI()
        app.run()
    except Exception as e:
        logger.critical(f"Критическая ошибка в main: {e}", exc_info=True)
        # Fallback messagebox if GUI was partially initialized
        try:
            messagebox.showerror("Критическая ошибка", f"Произошла неожиданная ошибка:\n{e}\n\nСмотрите ddos_monitor.log для деталей.")
        except: # If tkinter itself fails
            pass 
    finally:
        logger.info("🏁 Main: DDoS Protection Monitor завершил работу.")


if __name__ == "__main__":
    # Ensure 'logs' directory exists (moved to top level)
    # Ensure Scapy is configured correctly (e.g. Npcap on Windows)
    # For Windows, Scapy might need Npcap installed with "WinPcap API-compatible Mode"
    # For Linux, ensure libpcap is installed.
    main()
