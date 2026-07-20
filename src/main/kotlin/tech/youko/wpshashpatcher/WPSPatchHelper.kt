package tech.youko.wpshashpatcher

import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel

enum class Architecture {
    I386, AMD64, ARM64
}

private data class PatchSpec(
    val anchor: IntArray,
    val anchorMask: IntArray,
    val prologue: IntArray,
    val prologueMask: IntArray,
    val replacement: ByteArray
)

fun patchExecutableFile(file: File) {
    RandomAccessFile(file, "rw").use {
        val data: ByteBuffer = it.channel.map(FileChannel.MapMode.READ_WRITE, 0, it.channel.size())
        data.order(ByteOrder.LITTLE_ENDIAN)
        check(data.short == 0x5A4D.toShort()) { "Invalid DOS header." }
        data.position(0x3C)
        val peOffset = data.int
        data.position(peOffset)
        check(data.int == 0x4550) { "Invalid PE header." }
        val architecture = when (data.short) {
            0x014C.toShort() -> Architecture.I386
            0x8664.toShort() -> Architecture.AMD64
            0xAA64.toShort() -> Architecture.ARM64
            else -> error("Unsupported architecture.")
        }
        val sectionCount = data.short.toInt() and 0xFFFF
        val optionalHeaderSize = data.getShort(peOffset + 20).toInt() and 0xFFFF
        val sectionTableOffset = peOffset + 24 + optionalHeaderSize
        val textSection = (0 until sectionCount).firstNotNullOfOrNull { index ->
            val sectionOffset = sectionTableOffset + index * 40
            val name = ByteArray(8).also { name ->
                val sectionHeader = data.duplicate().apply { position(sectionOffset) }
                sectionHeader.get(name)
            }.takeWhile { byte -> byte != 0.toByte() }.toByteArray().toString(Charsets.US_ASCII)
            if (name == ".text") {
                val size = data.getInt(sectionOffset + 16)
                val offset = data.getInt(sectionOffset + 20)
                offset to size
            } else {
                null
            }
        } ?: error(".text section not found.")

        val (textOffset, textSize) = textSection
        check(textOffset >= 0 && textSize > 0 && textOffset.toLong() + textSize <= data.limit()) { "Invalid .text section range." }
        val text = data.duplicate().apply {
            position(textOffset)
            limit(textOffset + textSize)
        }.slice().order(ByteOrder.LITTLE_ENDIAN)
        patchExecutableFile(text, architecture)
    }
}

fun patchExecutableFile(data: ByteBuffer, architecture: Architecture) {
    val candidates = when (architecture) {
        Architecture.I386 -> listOf(Architecture.I386)
        Architecture.AMD64 -> listOf(Architecture.AMD64, Architecture.ARM64)
        Architecture.ARM64 -> listOf(Architecture.ARM64)
    }
    for (candidate in candidates) {
        if (tryPatchExecutableFile(data, patchSpec(candidate))) {
            return
        }
    }
    error("KRSAVerifyFile anchor is not unique or not found.")
}

private fun tryPatchExecutableFile(data: ByteBuffer, spec: PatchSpec): Boolean {
    val anchorMatches = findPattern(data, spec.anchor, spec.anchorMask, index = 0, maxMatches = 2)
    if (anchorMatches.size != 1) {
        return false
    }
    val anchorPos = anchorMatches.single()

    val prologuePos = findPattern(
        data, spec.prologue, spec.prologueMask, index = anchorPos, reverse = true, maxMatches = 1
    ).firstOrNull()
    val patched = spec.replacement.toPattern()
    val patchedPos = findPattern(
        data, patched, index = anchorPos, reverse = true, maxMatches = 1
    ).firstOrNull()
    val functionStart = listOfNotNull(prologuePos, patchedPos).maxOrNull() ?: error("KRSAVerifyFile function start not found.")

    if (functionStart == patchedPos) {
        return true
    }

    data.position(functionStart)
    data.put(spec.replacement)
    return true
}

private fun patchSpec(architecture: Architecture): PatchSpec = when (architecture) {
    Architecture.I386 -> PatchSpec(
        anchor = intArrayOf(0xC7, 0x06, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x46, 0x04, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x02, 0x33, 0xF6, 0x83, 0x7F, 0x14, 0x10, 0xC6, 0x45, 0xFC, 0x00),
        anchorMask = intArrayOf(0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
        prologue = intArrayOf(0x55, 0x8B, 0xEC),
        prologueMask = intArrayOf(0x00, 0x00, 0x00),
        replacement = bytesOf(0xB0, 0x01, 0xC3)
    )

    Architecture.AMD64 -> PatchSpec(
        anchor = intArrayOf(0x4C, 0x8D, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x89, 0x3F, 0x4C, 0x8D, 0x25, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x89, 0x67, 0x08),
        anchorMask = intArrayOf(0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00),
        prologue = intArrayOf(0x40, 0x53, 0x56),
        prologueMask = intArrayOf(0x00, 0x00, 0x00),
        replacement = bytesOf(0xB0, 0x01, 0xC3)
    )

    Architecture.ARM64 -> PatchSpec(
        anchor = intArrayOf(0x49, 0xA3, 0x02, 0xA9, 0x68, 0x1C, 0x00, 0xD0, 0x08, 0xA1, 0x1F, 0x91, 0x40, 0x03, 0x01, 0x91,0x48, 0x53, 0x00, 0xF9),
        anchorMask = intArrayOf(0x00, 0x00, 0x00, 0x00, 0xE0, 0xFF, 0xFF, 0x60, 0x00, 0xFC, 0x3F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
        prologue = intArrayOf(0xFD, 0x00, 0x00, 0xA9),
        prologueMask = intArrayOf(0x00, 0xFF, 0xFF, 0x00),
        replacement = bytesOf(0x20, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6)
    )
}
