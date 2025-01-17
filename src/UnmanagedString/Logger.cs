﻿using System.Drawing;
using Colorful;
using Console = Colorful.Console;

namespace UnmanagedString;

public class Logger
{
    private const string MessageStyle = "[{0}] [{1}] {2}";

    public static void Information(string message)
    {
        var replacements = new[]
        {
            new(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), Color.LightGreen),
            new Formatter("INFO", Color.LightGreen),
            new Formatter(message, Color.White)
        };
        Console.WriteLineFormatted(MessageStyle, Color.Gray, replacements);
    }

    public static void Success(string message)
    {
        var replacements = new[]
        {
            new(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), Color.Green),
            new Formatter("SUCCESS", Color.Green),
            new Formatter(message, Color.White)
        };
        Console.WriteLineFormatted(MessageStyle, Color.Gray, replacements);
    }

    public static void Warning(string message)
    {
        var replacements = new[]
        {
            new(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), Color.Yellow),
            new Formatter("WARNING", Color.Yellow),
            new Formatter(message, Color.White)
        };
        Console.WriteLineFormatted(MessageStyle, Color.Gray, replacements);
    }

    public static void Error(string message)
    {
        var replacements = new[]
        {
            new(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), Color.Red),
            new Formatter("ERROR", Color.Red),
            new Formatter(message, Color.White)
        };
        Console.WriteLineFormatted(MessageStyle, Color.Gray, replacements);
    }

    public static void Skipped(string message)
    {
        var replacements = new[]
        {
            new(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), Color.DarkGray),
            new Formatter("SKIPPED", Color.DarkGray),
            new Formatter(message, Color.White)
        };
        Console.WriteLineFormatted(MessageStyle, Color.Gray, replacements);
    }

    public static void Exception(Exception ex)
    {
        var replacements = new[]
        {
            new(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), Color.Red),
            new Formatter("EXCEPTION", Color.Red),
            new Formatter(ex.Message, Color.White)
        };
        Console.WriteLineFormatted(MessageStyle, Color.Gray, replacements);
    }
}