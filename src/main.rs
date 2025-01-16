mod welsib;

use std::env;
use std::io::{self, Read};
use ureq;
use std::error::Error;
use welsib::{digest, verify};

fn main() -> Result<(), Box<dyn Error>> {
    // Получаем аргумент командной строки (URL)
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Использование: echo <verifying key in hex string> | {} <URL>", args[0]);
        return Ok(());
    }
    let url = &args[1];

    // Читаем шестнадцатеричную строку из stdin
    let mut hex_input = String::new();
    io::stdin().read_to_string(&mut hex_input)?;
    let hex_input = hex_input.trim(); // Убираем лишние пробелы и переводы строк

    // Преобразуем шестнадцатеричную строку в Vec<u8>
    let verifying_key = hex2vec(hex_input.to_string());

    // Выполняем GET запрос
    let response = ureq::get(url).call()?;

    // Извлекаем заголовок "X-Welsib-Signature"
    if let Some(header_value) = response.header("X-Welsib-Signature") {
        // Парсим значение signature из заголовка
        if let Some(signature) = parse_signature(header_value) {
            // Убираем "R=" и ",S=", объединяем в одну hex-строку
            let cleaned_signature = signature.replace("R=", "").replace(",S=", "");

            // Преобразуем hex-строку в Vec<u8>
            let signature_bytes = hex2vec(cleaned_signature);

            // Читаем тело ответа (body) в виде Vec<u8>
            let mut body_bytes = Vec::new();
            response.into_reader().read_to_end(&mut body_bytes)?;

            // Верифицируем тело ответа
            let hash = unsafe { digest(&body_bytes) };
            let is_verified = unsafe { verify(&hash, &signature_bytes, &verifying_key) };

            if is_verified {
                println!("Верификация прошла успешно.");
            } else {
                eprintln!("Верификация не прошла успешно.");
            }
        } else {
            eprintln!("Не удалось извлечь signature из заголовка.");
        }
    } else {
        eprintln!("Заголовок X-Welsib-Signature не найден.");
    }

    Ok(())
}

// Функция для извлечения значения signature из заголовка
fn parse_signature(header_value: &str) -> Option<String> {
    // Ищем начало signature
    if let Some(start) = header_value.find("signature=\"") {
        let start = start + "signature=\"".len();
        // Ищем конец signature
        if let Some(end) = header_value[start..].find('"') {
            let signature = &header_value[start..start + end];
            return Some(signature.to_string());
        }
    }
    None
}

pub fn hex2vec(data: String) -> Vec<u8> {
    data.as_bytes()
    .chunks(2)
    .map(|b| u8::from_str_radix(&String::from_utf8(b.to_vec()).unwrap(), 16).unwrap())
    .collect::<Vec<u8>>()
}