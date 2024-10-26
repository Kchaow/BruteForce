package org.example;

import org.apache.commons.lang3.time.StopWatch;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public class Main {
    private static final String HASHES_FILE_NAME = "hashes.txt";
    private static final int WORD_LENGTH = 5;
    private static List<String> hashes;
    private static final String SYMBOLS = "abcdefghijklmnopqrstuvwxyz";
    private static final int TOTAL_NUMBER_OF_COMBINATIONS = (int) Math.pow(SYMBOLS.length(), WORD_LENGTH);
    private static final Map<String, Integer> letterNumToCommonNum = new HashMap<>();
    private static final AtomicInteger tryNumber = new AtomicInteger(0);
    private static volatile int currentPercent = 0;
    private static final AtomicInteger foundNumber = new AtomicInteger(0);

    static {
        letterNumToCommonNum.put("a", 10);
        letterNumToCommonNum.put("b", 11);
        letterNumToCommonNum.put("c", 12);
        letterNumToCommonNum.put("d", 13);
        letterNumToCommonNum.put("e", 14);
        letterNumToCommonNum.put("f", 15);
        letterNumToCommonNum.put("g", 16);
        letterNumToCommonNum.put("h", 17);
        letterNumToCommonNum.put("i", 18);
        letterNumToCommonNum.put("j", 19);
        letterNumToCommonNum.put("k", 20);
        letterNumToCommonNum.put("l", 21);
        letterNumToCommonNum.put("m", 22);
        letterNumToCommonNum.put("n", 23);
        letterNumToCommonNum.put("o", 24);
        letterNumToCommonNum.put("p", 25);
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, InterruptedException {
        ClassLoader classloader = Thread.currentThread().getContextClassLoader();
        URL hashesResource = classloader.getResource(HASHES_FILE_NAME);
        if (hashesResource == null) {
            System.out.println("Ошибка: файл с хэшами не найден");
            System.exit(-1);
        }
        System.out.printf("Хэши (SHA-256) считываются из файла %s\n", hashesResource.getPath());
        System.out.println("Будет предпринята попытка подобрать пароль к следующим хэшам:");
        try (BufferedReader buffer = new BufferedReader(new InputStreamReader(hashesResource.openStream()))) {
            hashes = buffer.lines().peek(System.out::println).toList();
        } catch (IOException e) {
            System.out.printf("Ошибка: не удалось прочитать файл %s\n", hashesResource.getPath());
            System.exit(-1);
        }
        System.out.print("Число потоков, которое будет задействовано >> ");
        Scanner scanner = new Scanner(System.in);
        int threadCount = scanner.nextInt();
        Map<Integer, String[]> threadWords = getBeginAndEndWordForThread(threadCount, TOTAL_NUMBER_OF_COMBINATIONS);
        List<Thread> threads = new ArrayList<>();
        for (int i = 0; i < threadCount; i++) {
            String[] words = threadWords.get(i);
            threads.add(new ThreadTask(words[0], words[1]));
        }
        StopWatch stopWatch = new StopWatch();
        stopWatch.start();
        threads.forEach(Thread::start);
        while (threads.stream().anyMatch(Thread::isAlive)) {
            Thread.sleep(1000);
            int percent = getPercent(tryNumber.get(), TOTAL_NUMBER_OF_COMBINATIONS);
            if (percent - currentPercent >= 3) {
                System.out.printf("Проанализировано %s%% комбинаций\n", percent);
                currentPercent = percent;
            }
        }
        stopWatch.stop();
        System.out.printf("Затрачено времени: %s секунд", stopWatch.getTime(TimeUnit.SECONDS));
    }

    private static int getPercent(int number, int of) {
        return 100 * number / of;
    }

    public static Map<Integer, String[]> getBeginAndEndWordForThread(int threadCount, int totalNumber) {
        Map<Integer, String[]> result = new HashMap<>();
        int currentWordNumber = 0;
        int step = totalNumber / threadCount;
        for (int i = 0; i < threadCount; i++) {
            if (i == threadCount -1) {
                result.put(i, new String[] {convertToWord(currentWordNumber), convertToWord(totalNumber-1)});
                break;
            }
            result.put(i, new String[] {convertToWord(currentWordNumber), convertToWord(currentWordNumber + step - 1)});
            currentWordNumber += step;
        }
        return result;
    }

    public static String convertToWord(int wordNumber) {
        String wordNumberProp = Integer.toString(wordNumber, SYMBOLS.length());
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(String.valueOf(SYMBOLS.charAt(0)).repeat(Math.max(0, WORD_LENGTH - wordNumberProp.length())));
        for (int i = 0; i < wordNumberProp.length(); i++) {
            Integer index = letterNumToCommonNum.get(wordNumberProp.charAt(i) + "");
            stringBuilder.append(index == null ? SYMBOLS.charAt(Integer.parseInt(wordNumberProp.charAt(i)+"")) : SYMBOLS.charAt(index));
        }
        return stringBuilder.toString();
    }

    private static class ThreadTask extends Thread {
        private final String initialWord;
        private final String stopWord;
        private final MessageDigest sha = MessageDigest.getInstance("SHA-256");
        private final MessageDigest md5 = MessageDigest.getInstance("MD5");

        public ThreadTask(String initialWord, String stopWord) throws NoSuchAlgorithmException {
            this.stopWord = stopWord;
            this.initialWord = initialWord;
        }

        @Override
        public void run() {
            String currentWord = initialWord;
            tryNumber.incrementAndGet();
            checkHashCoincidence(currentWord, sha);
            checkHashCoincidence(currentWord, md5);
            while (!currentWord.equals(stopWord) && !Thread.currentThread().isInterrupted()) {
                currentWord = getNextWord(currentWord);
                tryNumber.incrementAndGet();
                checkHashCoincidence(currentWord, sha);
                checkHashCoincidence(currentWord, md5);
            }
        }

        public String getNextWord(String word) {
            char[] wordArray = word.toCharArray();
            int length = wordArray.length;
            for (int i = length - 1; i >= 0; i--) {
                if (wordArray[i] != 'z') {
                    wordArray[i]++;
                    break;
                } else {
                    wordArray[i] = 'a';
                }
            }
            return new String(wordArray);
        }

        private String wordToHash(String word, MessageDigest md) {
            byte[]hashInBytes = md.digest(word.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hashInBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        }

        private void checkHashCoincidence(String word, MessageDigest md) {
            String hash = wordToHash(word, md);
            hashes.stream().filter(h -> h.equals(hash)).forEach(h -> {
                System.out.printf("%s >>> %s\n", h, word);
                foundNumber.incrementAndGet();
            });
            if (foundNumber.get() == hashes.size()) {
                Thread.currentThread().interrupt();
            }
        }
    }
}