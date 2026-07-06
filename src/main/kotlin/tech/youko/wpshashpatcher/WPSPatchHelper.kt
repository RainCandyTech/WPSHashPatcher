package tech.youko.wpshashpatcher

import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel

enum class Architecture {
    I386, AMD64
}

fun patchExecutableFile(file: File) {
    RandomAccessFile(file, "rw").use {
        val data = it.channel.map(FileChannel.MapMode.READ_WRITE, 0, it.channel.size())
        // 设置处理方式为小端
        data.order(ByteOrder.LITTLE_ENDIAN)
        // 判断DOS头
        check(data.short == 0x5A4D.toShort()) { "Invalid DOS header." }
        // 移动到PE头
        data.position(0x3C)
        data.position(data.int)
        // 判断PE头
        check(data.int == 0x4550) { "Invalid PE header." }
        // 获取可执行文件架构
        val architecture = when (data.short) {
            0x014C.toShort() -> Architecture.I386
            0x8664.toShort() -> Architecture.AMD64
            else -> error("Unsupported architecture.")
        }
        // 修补
        patchExecutableFile(data, architecture)
    }
}

fun patchExecutableFile(data: ByteBuffer, architecture: Architecture) {
    val (anchorPattern, anchorMask, replacementPattern, replacement) = when (architecture) {
        Architecture.I386 -> arrayOf(
            byteArrayOf(0x00, 0x02, 0x00, 0x00, 0x73, -0x01, 0x56),
            byteArrayOf(0x00, 0x00, 0x00, 0x00, 0x00, -0x01, 0x00),
            byteArrayOf(0x53, -0x75, -0x24),
            byteArrayOf(0x31, -0x40, -0x3D, -0x01)
        )

        Architecture.AMD64 -> arrayOf(
            byteArrayOf(0x63, -0x01, -0x01, -0x01, -0x01, 0x00, 0x02, 0x00, 0x00, 0x73),
            byteArrayOf(0x00, -0x01, -0x01, -0x01, -0x01, 0x00, 0x00, 0x00, 0x00, 0x00),
            byteArrayOf(0x48, -0x77, 0x5C, 0x24, 0x10),
            byteArrayOf(0x48, 0x31, -0x40, -0x3D, -0x01)
        )
    }

    // 以特征码模糊查找目标位置（仅锚点定位），最多查询2个结果以确保唯一性
    val anchorMatches = findPattern(data, anchorPattern, anchorMask, maxMatches = 2)
    check(anchorMatches.size == 1) { "Anchor pattern is not unique or not found." }
    val anchorPos = anchorMatches[0]

    // 从锚点向前逆向搜索原始函数起始字节（限制在 1024 字节内）
    data.position(anchorPos)
    val replacementMatches = findPattern(data, replacementPattern, reverse = true, maxMatches = 1)
    check(replacementMatches.isNotEmpty()) { "Function start not found." }
    val funcStart = replacementMatches[0]

    // 检查搜索到的位置是否在锚点前 1024 字节内
    check(anchorPos - funcStart <= 1024) { "Function start too far from anchor (exceed 1024 bytes)." }

    // 检查是否已打补丁（比较当前位置是否为 replacement 内容）
    data.position(funcStart)
    val alreadyPatched = (0 until replacement.size).all { data.get() == replacement[it] }
    if (alreadyPatched) {
        // 已打补丁，视为成功
        return
    }

    // 执行替换
    data.position(funcStart)
    data.put(replacement)
}
