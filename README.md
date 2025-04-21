# MVSA  
Инструмент для автоматического поиска уязвимостей в веб-приложениях.  
## Установка  
1. Клонировать репозиторий:  
   ```
   git clone https://github.com/Vses3va/mvsa
   cd mvsa
   ```

2. Установить зависимости:  
   ```bash
   pip install -r requirements.txt
   ```
## Использование
1. Запустить анализ:  
   ```bash
   python mvsa.py --code=app.py --report=report.json
   ```
   app.py - проверяемый код

2. Проверить отчет:  
   ```bash
   report.json
   ```
