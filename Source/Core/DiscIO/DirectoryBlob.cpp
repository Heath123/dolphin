// Copyright 2008 Dolphin Emulator Project
// Licensed under GPLv2+
// Refer to the license.txt file included.

#include "DiscIO/DirectoryBlob.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <locale>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <variant>
#include <vector>
#include <iostream>

#include "Common/Align.h"
#include "Common/Assert.h"
#include "Common/CommonPaths.h"
#include "Common/CommonTypes.h"
#include "Common/File.h"
#include "Common/FileUtil.h"
#include "Common/Logging/Log.h"
#include "Common/StringUtil.h"
#include "Common/Swap.h"
#include "Core/Boot/DolReader.h"
#include "Core/IOS/ES/Formats.h"
#include "DiscIO/Blob.h"
#include "DiscIO/VolumeWii.h"
#include "DiscIO/WiiEncryptionCache.h"
#include "Mod.h"

namespace DiscIO
{
// Reads as many bytes as the vector fits (or less, if the file is smaller).
// Returns the number of bytes read.
static size_t ReadFileToVector(const std::string& path, std::vector<u8>* vector);

static void PadToAddress(u64 start_address, u64* address, u64* length, u8** buffer);
static void Write32(u32 data, u32 offset, std::vector<u8>* buffer);

static u32 ComputeNameSize(const File::FSTEntry& parent_entry);
static std::string ASCIIToUppercase(std::string str);
static void ConvertUTF8NamesToSHIFTJIS(File::FSTEntry* parent_entry);

enum class PartitionType : u32
{
  Game = 0,
  Update = 1,
  Channel = 2,
  // There are more types used by Super Smash Bros. Brawl, but they don't have special names
};

// 0xFF is an arbitrarily picked value. Note that we can't use 0x00, because that means NTSC-J
constexpr u32 INVALID_REGION = 0xFF;

constexpr u32 PARTITION_DATA_OFFSET = 0x20000;

constexpr u8 ENTRY_SIZE = 0x0c;
constexpr u8 FILE_ENTRY = 0;
constexpr u8 DIRECTORY_ENTRY = 1;

DiscContent::DiscContent(u64 offset, u64 size, const std::string& path)
    : m_offset(offset), m_size(size), m_content_source(path)
{
}

DiscContent::DiscContent(u64 offset, u64 size, const u8* data)
    : m_offset(offset), m_size(size), m_content_source(data)
{
}

DiscContent::DiscContent(u64 offset, u64 size, DirectoryBlobReader* blob)
    : m_offset(offset), m_size(size), m_content_source(blob)
{
}

DiscContent::DiscContent(u64 offset) : m_offset(offset)
{
}

u64 DiscContent::GetOffset() const
{
  return m_offset;
}

u64 DiscContent::GetEndOffset() const
{
  return m_offset + m_size;
}

u64 DiscContent::GetSize() const
{
  return m_size;
}

bool DiscContent::Read(u64* offset, u64* length, u8** buffer) const
{
  if (m_size == 0)
    return true;

  DEBUG_ASSERT(*offset >= m_offset);
  const u64 offset_in_content = *offset - m_offset;

  if (offset_in_content < m_size)
  {
    const u64 bytes_to_read = std::min(m_size - offset_in_content, *length);

    if (std::holds_alternative<std::string>(m_content_source))
    {
      File::IOFile file(std::get<std::string>(m_content_source), "rb");
      if (!file.Seek(offset_in_content, SEEK_SET) || !file.ReadBytes(*buffer, bytes_to_read))
        return false;
    }
    else if (std::holds_alternative<const u8*>(m_content_source))
    {
      const u8* const content_pointer = std::get<const u8*>(m_content_source) + offset_in_content;
      std::copy(content_pointer, content_pointer + bytes_to_read, *buffer);
    }
    else
    {
      DirectoryBlobReader* blob = std::get<DirectoryBlobReader*>(m_content_source);
      const u64 decrypted_size = m_size * VolumeWii::BLOCK_DATA_SIZE / VolumeWii::BLOCK_TOTAL_SIZE;
      if (!blob->EncryptPartitionData(offset_in_content, bytes_to_read, *buffer, m_offset,
                                      decrypted_size))
      {
        return false;
      }
    }

    *length -= bytes_to_read;
    *buffer += bytes_to_read;
    *offset += bytes_to_read;
  }

  return true;
}

void DiscContentContainer::Add(u64 offset, u64 size, const std::string& path)
{
  if (size != 0)
    m_contents.emplace(offset, size, path);
}

void DiscContentContainer::Add(u64 offset, u64 size, const u8* data)
{
  if (size != 0)
    m_contents.emplace(offset, size, data);
}

void DiscContentContainer::Add(u64 offset, u64 size, DirectoryBlobReader* blob)
{
  if (size != 0)
    m_contents.emplace(offset, size, blob);
}

u64 DiscContentContainer::CheckSizeAndAdd(u64 offset, const std::string& path)
{
  const u64 size = File::GetSize(path);
  Add(offset, size, path);
  return size;
}

u64 DiscContentContainer::CheckSizeAndAdd(u64 offset, u64 max_size, const std::string& path)
{
  const u64 size = std::min(File::GetSize(path), max_size);
  Add(offset, size, path);
  return size;
}

bool DiscContentContainer::Read(u64 offset, u64 length, u8* buffer) const
{
  // Determine which DiscContent the offset refers to
  std::set<DiscContent>::const_iterator it = m_contents.upper_bound(DiscContent(offset));

  while (it != m_contents.end() && length > 0)
  {
    // Zero fill to start of DiscContent data
    PadToAddress(it->GetOffset(), &offset, &length, &buffer);

    if (!it->Read(&offset, &length, &buffer))
      return false;

    ++it;
    DEBUG_ASSERT(it == m_contents.end() || it->GetOffset() >= offset);
  }

  // Zero fill if we went beyond the last DiscContent
  std::fill_n(buffer, static_cast<size_t>(length), 0);

  return true;
}

static std::optional<PartitionType> ParsePartitionDirectoryName(const std::string& name)
{
  if (name.size() < 2)
    return {};

  if (!strcasecmp(name.c_str(), "DATA"))
    return PartitionType::Game;
  if (!strcasecmp(name.c_str(), "UPDATE"))
    return PartitionType::Update;
  if (!strcasecmp(name.c_str(), "CHANNEL"))
    return PartitionType::Channel;

  if (name[0] == 'P' || name[0] == 'p')
  {
    // e.g. "P-HA8E" (normally only used for Super Smash Bros. Brawl's VC partitions)
    if (name[1] == '-' && name.size() == 6)
    {
      const u32 result = Common::swap32(reinterpret_cast<const u8*>(name.data() + 2));
      return static_cast<PartitionType>(result);
    }

    // e.g. "P0"
    if (std::all_of(name.cbegin() + 1, name.cend(), [](char c) { return c >= '0' && c <= '9'; }))
    {
      u32 result;
      if (TryParse(name.substr(1), &result))
        return static_cast<PartitionType>(result);
    }
  }

  return {};
}

static bool IsDirectorySeparator(char c)
{
  return c == '/'
#ifdef _WIN32
         || c == '\\'
#endif
      ;
}

static bool PathCharactersEqual(char a, char b)
{
  return a == b || (IsDirectorySeparator(a) && IsDirectorySeparator(b));
}

static bool PathEndsWith(const std::string& path, const std::string& suffix)
{
  if (suffix.size() > path.size())
    return false;

  std::string::const_iterator path_iterator = path.cend() - suffix.size();
  std::string::const_iterator suffix_iterator = suffix.cbegin();
  while (path_iterator != path.cend())
  {
    if (!PathCharactersEqual(*path_iterator, *suffix_iterator))
      return false;
    path_iterator++;
    suffix_iterator++;
  }

  return true;
}

static bool IsValidDirectoryBlob(const std::string& dol_path, std::string* partition_root,
                                 std::string* true_root = nullptr)
{
  if (!PathEndsWith(dol_path, "/sys/main.dol"))
    return false;

  const size_t chars_to_remove = std::string("sys/main.dol").size();
  *partition_root = dol_path.substr(0, dol_path.size() - chars_to_remove);

  if (File::GetSize(*partition_root + "sys/boot.bin") < 0x20)
    return false;

#ifdef _WIN32
  constexpr const char* dir_separator = "/\\";
#else
  constexpr char dir_separator = '/';
#endif
  if (true_root)
  {
    *true_root =
        dol_path.substr(0, dol_path.find_last_of(dir_separator, partition_root->size() - 2) + 1);
  }

  return true;
}

static bool ExistsAndIsValidDirectoryBlob(const std::string& dol_path)
{
  std::string partition_root;
  return File::Exists(dol_path) && IsValidDirectoryBlob(dol_path, &partition_root);
}

static bool IsInFilesDirectory(const std::string& path)
{
  size_t files_pos = std::string::npos;
  while (true)
  {
    files_pos = path.rfind("files", files_pos);
    if (files_pos == std::string::npos)
      return false;

    const size_t slash_before_pos = files_pos - 1;
    const size_t slash_after_pos = files_pos + 5;
    if ((files_pos == 0 || IsDirectorySeparator(path[slash_before_pos])) &&
        (slash_after_pos == path.size() || (IsDirectorySeparator(path[slash_after_pos]))) &&
        ExistsAndIsValidDirectoryBlob(path.substr(0, files_pos) + "sys/main.dol"))
    {
      return true;
    }

    --files_pos;
  }
}

static bool IsMainDolForNonGamePartition(const std::string& path)
{
  std::string partition_root, true_root;
  if (!IsValidDirectoryBlob(path, &partition_root, &true_root))
    return false;  // This is not a /sys/main.dol

  std::string partition_directory_name = partition_root.substr(true_root.size());
  partition_directory_name.pop_back();  // Remove trailing slash
  const std::optional<PartitionType> partition_type =
      ParsePartitionDirectoryName(partition_directory_name);
  if (!partition_type || *partition_type == PartitionType::Game)
    return false;  // volume_path is the game partition's /sys/main.dol

  const File::FSTEntry true_root_entry = File::ScanDirectoryTree(true_root, false);

  // TODO: patch this in case a dol is added/changed??? But it should be there already, so probably not needed
  // File::AddToTreeRecursive(true_root_entry, "/", "/Race/Course", "test.szs", "/media/heath/Windows/Users/User/Desktop/test.txt");

  for (const File::FSTEntry& entry : true_root_entry.children)
  {
    if (entry.isDirectory &&
        ParsePartitionDirectoryName(entry.virtualName) == PartitionType::Game &&
        ExistsAndIsValidDirectoryBlob(entry.physicalName + "/sys/main.dol"))
    {
      return true;  // volume_path is the /sys/main.dol for a non-game partition
    }
  }

  return false;  // volume_path is the game partition's /sys/main.dol
}

bool ShouldHideFromGameList(const std::string& volume_path)
{
  return IsInFilesDirectory(volume_path) || IsMainDolForNonGamePartition(volume_path);
}

std::unique_ptr<DirectoryBlobReader> DirectoryBlobReader::Create(const std::string& dol_path)
{
  std::string partition_root, true_root;
  if (!IsValidDirectoryBlob(dol_path, &partition_root, &true_root))
    return nullptr;

  return std::unique_ptr<DirectoryBlobReader>(new DirectoryBlobReader(partition_root, true_root));
}

DirectoryBlobReader::DirectoryBlobReader(const std::string& game_partition_root,
                                         const std::string& true_root)
    : m_encryption_cache(this)
{
  DirectoryBlobPartition game_partition(game_partition_root, {});
  m_is_wii = game_partition.IsWii();

  if (!m_is_wii)
  {
    m_gamecube_pseudopartition = std::move(game_partition);
    m_data_size = m_gamecube_pseudopartition.GetDataSize();
    m_encrypted = false;
  }
  else
  {
    SetNonpartitionDiscHeader(game_partition.GetHeader(), game_partition_root);
    SetWiiRegionData(game_partition_root);

    std::vector<PartitionWithType> partitions;
    partitions.emplace_back(std::move(game_partition), PartitionType::Game);

    std::string game_partition_directory_name = game_partition_root.substr(true_root.size());
    game_partition_directory_name.pop_back();  // Remove trailing slash
    if (ParsePartitionDirectoryName(game_partition_directory_name) == PartitionType::Game)
    {
      const File::FSTEntry true_root_entry = File::ScanDirectoryTree(true_root, false);

      // TODO? But it isn't recursive so it won't do much, so probably not needed
      // File::AddToTreeRecursive(true_root_entry, "/", "/Race/Course", "test.szs", "/media/heath/Windows/Users/User/Desktop/test.txt");

      for (const File::FSTEntry& entry : true_root_entry.children)
      {
        if (entry.isDirectory)
        {
          const std::optional<PartitionType> type = ParsePartitionDirectoryName(entry.virtualName);
          if (type && *type != PartitionType::Game)
          {
            partitions.emplace_back(DirectoryBlobPartition(entry.physicalName + "/", m_is_wii),
                                    *type);
          }
        }
      }
    }

    SetPartitions(std::move(partitions));
  }
}

bool DirectoryBlobReader::Read(u64 offset, u64 length, u8* buffer)
{
  if (offset + length > m_data_size)
    return false;

  return (m_is_wii ? m_nonpartition_contents : m_gamecube_pseudopartition.GetContents())
      .Read(offset, length, buffer);
}

const DirectoryBlobPartition* DirectoryBlobReader::GetPartition(u64 offset, u64 size,
                                                                u64 partition_data_offset) const
{
  const auto it = m_partitions.find(partition_data_offset);
  if (it == m_partitions.end())
    return nullptr;

  if (offset + size > it->second.GetDataSize())
    return nullptr;

  return &it->second;
}

bool DirectoryBlobReader::SupportsReadWiiDecrypted(u64 offset, u64 size,
                                                   u64 partition_data_offset) const
{
  return static_cast<bool>(GetPartition(offset, size, partition_data_offset));
}

bool DirectoryBlobReader::ReadWiiDecrypted(u64 offset, u64 size, u8* buffer,
                                           u64 partition_data_offset)
{
  const DirectoryBlobPartition* partition = GetPartition(offset, size, partition_data_offset);
  if (!partition)
    return false;

  return partition->GetContents().Read(offset, size, buffer);
}

bool DirectoryBlobReader::EncryptPartitionData(u64 offset, u64 size, u8* buffer,
                                               u64 partition_data_offset,
                                               u64 partition_data_decrypted_size)
{
  auto it = m_partitions.find(partition_data_offset);
  if (it == m_partitions.end())
    return false;

  if (!m_encrypted)
    return it->second.GetContents().Read(offset, size, buffer);

  return m_encryption_cache.EncryptGroups(offset, size, buffer, partition_data_offset,
                                          partition_data_decrypted_size, it->second.GetKey());
}

BlobType DirectoryBlobReader::GetBlobType() const
{
  return BlobType::DIRECTORY;
}

u64 DirectoryBlobReader::GetRawSize() const
{
  // Not implemented
  return 0;
}

u64 DirectoryBlobReader::GetDataSize() const
{
  return m_data_size;
}

void DirectoryBlobReader::SetNonpartitionDiscHeader(const std::vector<u8>& partition_header,
                                                    const std::string& game_partition_root)
{
  constexpr u64 NONPARTITION_DISCHEADER_ADDRESS = 0;
  constexpr u64 NONPARTITION_DISCHEADER_SIZE = 0x100;

  m_disc_header_nonpartition.resize(NONPARTITION_DISCHEADER_SIZE);
  const size_t header_bin_bytes_read =
      ReadFileToVector(game_partition_root + "disc/header.bin", &m_disc_header_nonpartition);

  // If header.bin is missing or smaller than expected, use the content of sys/boot.bin instead
  std::copy(partition_header.data() + header_bin_bytes_read,
            partition_header.data() + m_disc_header_nonpartition.size(),
            m_disc_header_nonpartition.data() + header_bin_bytes_read);

  // 0x60 and 0x61 are the only differences between the partition and non-partition headers
  if (header_bin_bytes_read < 0x60)
    m_disc_header_nonpartition[0x60] = 0;
  if (header_bin_bytes_read < 0x61)
    m_disc_header_nonpartition[0x61] = 0;

  m_encrypted = std::all_of(m_disc_header_nonpartition.data() + 0x60,
                            m_disc_header_nonpartition.data() + 0x64, [](u8 x) { return x == 0; });

  m_nonpartition_contents.Add(NONPARTITION_DISCHEADER_ADDRESS, m_disc_header_nonpartition);
}

void DirectoryBlobReader::SetWiiRegionData(const std::string& game_partition_root)
{
  m_wii_region_data.resize(0x10, 0x00);
  m_wii_region_data.resize(0x20, 0x80);
  Write32(INVALID_REGION, 0, &m_wii_region_data);

  const std::string region_bin_path = game_partition_root + "disc/region.bin";
  const size_t bytes_read = ReadFileToVector(region_bin_path, &m_wii_region_data);
  if (bytes_read < 0x4)
    ERROR_LOG_FMT(DISCIO, "Couldn't read region from {}", region_bin_path);
  else if (bytes_read < 0x20)
    ERROR_LOG_FMT(DISCIO, "Couldn't read age ratings from {}", region_bin_path);

  constexpr u64 WII_REGION_DATA_ADDRESS = 0x4E000;
  [[maybe_unused]] constexpr u64 WII_REGION_DATA_SIZE = 0x20;
  m_nonpartition_contents.Add(WII_REGION_DATA_ADDRESS, m_wii_region_data);
}

void DirectoryBlobReader::SetPartitions(std::vector<PartitionWithType>&& partitions)
{
  std::sort(partitions.begin(), partitions.end(),
            [](const PartitionWithType& lhs, const PartitionWithType& rhs) {
              if (lhs.type == rhs.type)
                return lhs.partition.GetRootDirectory() < rhs.partition.GetRootDirectory();

              // Ascending sort by partition type, except Update (1) comes before before Game (0)
              return (lhs.type > PartitionType::Update || rhs.type > PartitionType::Update) ?
                         lhs.type < rhs.type :
                         lhs.type > rhs.type;
            });

  u32 subtable_1_size = 0;
  while (subtable_1_size < partitions.size() && subtable_1_size < 3 &&
         partitions[subtable_1_size].type <= PartitionType::Channel)
  {
    ++subtable_1_size;
  }
  const u32 subtable_2_size = static_cast<u32>(partitions.size() - subtable_1_size);

  constexpr u32 PARTITION_TABLE_ADDRESS = 0x40000;
  constexpr u32 PARTITION_SUBTABLE1_OFFSET = 0x20;
  constexpr u32 PARTITION_SUBTABLE2_OFFSET = 0x40;
  m_partition_table.resize(PARTITION_SUBTABLE2_OFFSET + subtable_2_size * 8);

  Write32(subtable_1_size, 0x0, &m_partition_table);
  Write32((PARTITION_TABLE_ADDRESS + PARTITION_SUBTABLE1_OFFSET) >> 2, 0x4, &m_partition_table);
  if (subtable_2_size != 0)
  {
    Write32(subtable_2_size, 0x8, &m_partition_table);
    Write32((PARTITION_TABLE_ADDRESS + PARTITION_SUBTABLE2_OFFSET) >> 2, 0xC, &m_partition_table);
  }

  constexpr u64 STANDARD_UPDATE_PARTITION_ADDRESS = 0x50000;
  constexpr u64 STANDARD_GAME_PARTITION_ADDRESS = 0xF800000;
  u64 partition_address = STANDARD_UPDATE_PARTITION_ADDRESS;
  u64 offset_in_table = PARTITION_SUBTABLE1_OFFSET;
  for (size_t i = 0; i < partitions.size(); ++i)
  {
    if (i == subtable_1_size)
      offset_in_table = PARTITION_SUBTABLE2_OFFSET;

    if (partitions[i].type == PartitionType::Game)
      partition_address = std::max(partition_address, STANDARD_GAME_PARTITION_ADDRESS);

    Write32(static_cast<u32>(partition_address >> 2), offset_in_table, &m_partition_table);
    offset_in_table += 4;
    Write32(static_cast<u32>(partitions[i].type), offset_in_table, &m_partition_table);
    offset_in_table += 4;

    SetPartitionHeader(&partitions[i].partition, partition_address);

    const u64 data_size = partitions[i].partition.GetDataSize();
    m_partitions.emplace(partition_address + PARTITION_DATA_OFFSET,
                         std::move(partitions[i].partition));
    m_nonpartition_contents.Add(partition_address + PARTITION_DATA_OFFSET, data_size, this);
    const u64 unaligned_next_partition_address = VolumeWii::EncryptedPartitionOffsetToRawOffset(
        data_size, Partition(partition_address), PARTITION_DATA_OFFSET);
    partition_address = Common::AlignUp(unaligned_next_partition_address, 0x10000ull);
  }
  m_data_size = partition_address;

  m_nonpartition_contents.Add(PARTITION_TABLE_ADDRESS, m_partition_table);
}

// This function sets the header that's shortly before the start of the encrypted
// area, not the header that's right at the beginning of the encrypted area
void DirectoryBlobReader::SetPartitionHeader(DirectoryBlobPartition* partition,
                                             u64 partition_address)
{
  constexpr u32 TICKET_OFFSET = 0x0;
  constexpr u32 TICKET_SIZE = 0x2a4;
  constexpr u32 TMD_OFFSET = 0x2c0;
  constexpr u32 MAX_TMD_SIZE = 0x49e4;
  constexpr u32 H3_OFFSET = 0x4000;
  constexpr u32 H3_SIZE = 0x18000;

  const std::string& partition_root = partition->GetRootDirectory();

  const u64 ticket_size = m_nonpartition_contents.CheckSizeAndAdd(
      partition_address + TICKET_OFFSET, TICKET_SIZE, partition_root + "ticket.bin");

  const u64 tmd_size = m_nonpartition_contents.CheckSizeAndAdd(
      partition_address + TMD_OFFSET, MAX_TMD_SIZE, partition_root + "tmd.bin");

  const u64 cert_offset = Common::AlignUp(TMD_OFFSET + tmd_size, 0x20ull);
  const u64 max_cert_size = H3_OFFSET - cert_offset;
  const u64 cert_size = m_nonpartition_contents.CheckSizeAndAdd(
      partition_address + cert_offset, max_cert_size, partition_root + "cert.bin");

  m_nonpartition_contents.CheckSizeAndAdd(partition_address + H3_OFFSET, H3_SIZE,
                                          partition_root + "h3.bin");

  constexpr u32 PARTITION_HEADER_SIZE = 0x1c;
  const u64 data_size = Common::AlignUp(partition->GetDataSize(), 0x7c00) / 0x7c00 * 0x8000;
  m_partition_headers.emplace_back(PARTITION_HEADER_SIZE);
  std::vector<u8>& partition_header = m_partition_headers.back();
  Write32(static_cast<u32>(tmd_size), 0x0, &partition_header);
  Write32(TMD_OFFSET >> 2, 0x4, &partition_header);
  Write32(static_cast<u32>(cert_size), 0x8, &partition_header);
  Write32(static_cast<u32>(cert_offset >> 2), 0x0C, &partition_header);
  Write32(H3_OFFSET >> 2, 0x10, &partition_header);
  Write32(PARTITION_DATA_OFFSET >> 2, 0x14, &partition_header);
  Write32(static_cast<u32>(data_size >> 2), 0x18, &partition_header);

  m_nonpartition_contents.Add(partition_address + TICKET_SIZE, partition_header);

  std::vector<u8> ticket_buffer(ticket_size);
  m_nonpartition_contents.Read(partition_address + TICKET_OFFSET, ticket_size,
                               ticket_buffer.data());
  IOS::ES::TicketReader ticket(std::move(ticket_buffer));
  if (ticket.IsValid())
    partition->SetKey(ticket.GetTitleKey());
}

DirectoryBlobPartition::DirectoryBlobPartition(const std::string& root_directory,
                                               std::optional<bool> is_wii)
    : m_root_directory(root_directory)
{
  SetDiscHeaderAndDiscType(is_wii);
  SetBI2();
  BuildFST(SetDOL(SetApploader()));
}

void DirectoryBlobPartition::SetDiscHeaderAndDiscType(std::optional<bool> is_wii)
{
  constexpr u64 DISCHEADER_ADDRESS = 0;
  constexpr u64 DISCHEADER_SIZE = 0x440;

  m_disc_header.resize(DISCHEADER_SIZE);
  const std::string boot_bin_path = m_root_directory + "sys/boot.bin";
  if (ReadFileToVector(boot_bin_path, &m_disc_header) < 0x20)
    ERROR_LOG_FMT(DISCIO, "{} doesn't exist or is too small", boot_bin_path);

  m_contents.Add(DISCHEADER_ADDRESS, m_disc_header);

  if (is_wii.has_value())
  {
    m_is_wii = *is_wii;
  }
  else
  {
    m_is_wii = Common::swap32(&m_disc_header[0x18]) == 0x5d1c9ea3;
    const bool is_gc = Common::swap32(&m_disc_header[0x1c]) == 0xc2339f3d;
    if (m_is_wii == is_gc)
      ERROR_LOG_FMT(DISCIO, "Couldn't detect disc type based on {}", boot_bin_path);
  }

  m_address_shift = m_is_wii ? 2 : 0;
}

void DirectoryBlobPartition::SetBI2()
{
  constexpr u64 BI2_ADDRESS = 0x440;
  constexpr u64 BI2_SIZE = 0x2000;
  m_bi2.resize(BI2_SIZE);

  if (!m_is_wii)
    Write32(INVALID_REGION, 0x18, &m_bi2);

  const std::string bi2_path = m_root_directory + "sys/bi2.bin";
  const size_t bytes_read = ReadFileToVector(bi2_path, &m_bi2);
  if (!m_is_wii && bytes_read < 0x1C)
    ERROR_LOG_FMT(DISCIO, "Couldn't read region from {}", bi2_path);

  m_contents.Add(BI2_ADDRESS, m_bi2);
}

u64 DirectoryBlobPartition::SetApploader()
{
  bool success = false;

  const std::string path = m_root_directory + "sys/apploader.img";
  File::IOFile file(path, "rb");
  m_apploader.resize(file.GetSize());
  if (m_apploader.size() < 0x20 || !file.ReadBytes(m_apploader.data(), m_apploader.size()))
  {
    ERROR_LOG_FMT(DISCIO, "{} couldn't be accessed or is too small", path);
  }
  else
  {
    const size_t apploader_size = 0x20 + Common::swap32(*(u32*)&m_apploader[0x14]) +
                                  Common::swap32(*(u32*)&m_apploader[0x18]);
    if (apploader_size != m_apploader.size())
      ERROR_LOG_FMT(DISCIO, "{} is the wrong size... Is it really an apploader?", path);
    else
      success = true;
  }

  if (!success)
  {
    m_apploader.resize(0x20);
    // Make sure BS2 HLE doesn't try to run the apploader
    Write32(static_cast<u32>(-1), 0x10, &m_apploader);
  }

  constexpr u64 APPLOADER_ADDRESS = 0x2440;

  m_contents.Add(APPLOADER_ADDRESS, m_apploader);

  // Return DOL address, 32 byte aligned (plus 32 byte padding)
  return Common::AlignUp(APPLOADER_ADDRESS + m_apploader.size() + 0x20, 0x20ull);
}

u64 DirectoryBlobPartition::SetDOL(u64 dol_address)
{
  const u64 dol_size = m_contents.CheckSizeAndAdd(dol_address, m_root_directory + "sys/main.dol");

  Write32(static_cast<u32>(dol_address >> m_address_shift), 0x0420, &m_disc_header);

  // Return FST address, 32 byte aligned (plus 32 byte padding)
  return Common::AlignUp(dol_address + dol_size + 0x20, 0x20ull);
}

void DirectoryBlobPartition::BuildFST(u64 fst_address)
{
  m_fst_data.clear();

  File::FSTEntry rootEntry = File::ScanDirectoryTree(m_root_directory + "files/", true);

  // TODO: rename to AddOrReplaceFileInTree or something? InjectToTree?

  // TODO: Remove
  // Create fake parent
  File::FSTEntry parent_entry;
  parent_entry.physicalName = ""; // TODO: need to use real physical name?
  parent_entry.isDirectory = true;
  parent_entry.size = 0;

  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "40.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/kinoko_course/mushroom_peaks.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "40_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/kinoko_course/mushroom_peaks.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "41.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/old_garden_ds/chomp_valley.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "41_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/old_garden_ds/chomp_valley.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "44.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/koopa_course/snes_bowser_castle_2.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "44_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/koopa_course/snes_bowser_castle_2.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "45.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/old_falls_ds/codename_bigbox.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "45_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/old_falls_ds/codename_bigbox.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "46.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/old_koopa_gba/thwomp_cave.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "46_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/old_koopa_gba/thwomp_cave.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "47.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/old_mario_sfc/snes_mario_circuit_1.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "47_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/old_mario_sfc/snes_mario_circuit_1.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "48.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/old_heyho_gba/gba_cheep_cheep_island.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "48_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/old_heyho_gba/gba_cheep_cheep_island.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "49.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/old_sherbet_64/northpole_slide.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "49_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/old_sherbet_64/northpole_slide.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "4A.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/rainbow_course/snes_rainbow_road.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "4A_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/rainbow_course/snes_rainbow_road.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "4B.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/ridgehighway_course/space_road.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "4B_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/ridgehighway_course/space_road.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "4C.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/old_peach_gc/green_hill_zone.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "4C_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/old_peach_gc/green_hill_zone.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "4D.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/truck_course/asdf_course.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "4D_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/truck_course/asdf_course.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "4E.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/beginner_course/luigis_island.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "4E_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/beginner_course/luigis_island.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "4F.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/old_donkey_64/jungle_safari.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "4F_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/old_donkey_64/jungle_safari.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "50.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/senior_course/penguin_canyon.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "50_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/senior_course/penguin_canyon.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "51.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/volcano_course/incendia_castle.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "51_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/volcano_course/incendia_castle.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "52.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/farm_course/sunset_forest.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "52_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/farm_course/sunset_forest.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "53.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/old_waluigi_gc/warios_lair.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "53_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/old_waluigi_gc/warios_lair.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "54.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/boardcross_course/haunted_woods.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "54_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/boardcross_course/haunted_woods.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "55.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/castle_course/rezway.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "55_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/castle_course/rezway.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "56.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/old_mario_gc/kartwood_creek.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "56_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/old_mario_gc/kartwood_creek.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "57.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/treehouse_course/fishdom_island.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "57_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/treehouse_course/fishdom_island.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "58.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/shopping_course/gcn_rainbow_road.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "58_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/shopping_course/gcn_rainbow_road.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "59.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/old_mario_64/n64_royal_raceway.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "59_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/old_mario_64/n64_royal_raceway.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "5A.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/old_town_ds/n64_yoshi_valley.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "5A_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/old_town_ds/n64_yoshi_valley.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "5B.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/old_donkey_gc/ds_airship_fortress.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "5B_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/old_donkey_gc/ds_airship_fortress.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "5C.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/SixKingLabyrinth/SixKingLabyrinth129.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "5C_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/SixKingLabyrinth/SixKingLabyrinth129.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "5D.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/desert_course/gba_rainbow_road.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "5D_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/desert_course/gba_rainbow_road.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "5E.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/factory_course/gba_sky_garden.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "5E_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/factory_course/gba_sky_garden.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "5F.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Level2/NewCT1.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "5F_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Level2/NewCT1.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "60.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Level2/NewCT2.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "60_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Level2/NewCT2.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "61.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Level2/NewCT3.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "61_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Level2/NewCT3.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "62.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Level2/NewCT4.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "62_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Level2/NewCT4.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "63.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Level2/NewCT5.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "63_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Level2/NewCT5.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "64.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Level2/NewCT6.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "64_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Level2/NewCT6.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "65.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Level2/NewCT7.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "65_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Level2/NewC7.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "66.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Level2/NewCT8.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "66_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Level2/NewCT8.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "67.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Level2/NewCT9.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "67_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Level2/NewCT9.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "68.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Level2/NewCTA.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "68_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Level2/NewCTA.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "69.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Level2/NewCTB.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "69_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Level2/NewCTB.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "6A.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Level2/NewCTC.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "6A_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Level2/NewCTC_d.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "6B.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Level2/NewCTD.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "6B_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Level2/NewCTD.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "6C.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Level2/NewCTE.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "6C_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Level2/NewCTE.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "6D.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Level2/NewCTF.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "6D_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Level2/NewCTF.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "6E.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Level2/NewCTG.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "6E_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Level2/NewCTG.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "6F.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/6F.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "6F_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/6F.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "70.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/70.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "70_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/70.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "71.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/71.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "71_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/71.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "72.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/72.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "72_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/72.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "73.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/73.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "73_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/73.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "74.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/74.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "74_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/74.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "75.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/75.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "75_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/75.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "76.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/76.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "76_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/76.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "77.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/77.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "77_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/77.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "78.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/78.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "78_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/78.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "79.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/79.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "79_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/79.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "7A.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/7A.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "7A_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/7A.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "7B.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/7B.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "7B_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/7B.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "7C.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/7C.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "7C_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/7C.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "7D.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/7D.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "7D_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/7D.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "7E.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/7E.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "7E_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/7E.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "7F.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/7F.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "7F_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/7F.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "80.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/80.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "80_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/80.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "81.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/81.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "81_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/81.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "82.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/82.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "82_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/82.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "83.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/83.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "83_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/83.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "84.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/84.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "84_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/84.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "85.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/85.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "85_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/85.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "86.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/86.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "86_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/86.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "87.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/87.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "87_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/87.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "88.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/88.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "88_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/88.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "89.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/89.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "89_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/89.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "8A.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/8A.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "8A_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/8A.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "8B.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/8B.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "8B_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/8B_d.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "8C.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/8C.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "8C_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/8C.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "8D.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/8D.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "8D_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/8D.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "8E.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/8E.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "8E_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/8E.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "8F.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/8F.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "8F_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/8F.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "90.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/90.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "90_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/90.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "91.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/91.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "91_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/91.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "92.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/92.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "92_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/92.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "93.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/93.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "93_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/93.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "94.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/94.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "94_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/94.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "95.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/95.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "95_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/95.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "96.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/96.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "96_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/96.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "97.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/97.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "97_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/97_d.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "98.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/98.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "98_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/98.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "99.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/99.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "99_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/99.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "9A.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/9A.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "9A_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/9A.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "9B.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/9B.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "9B_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/9B.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "9C.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/9C.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "9C_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/9C.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "9D.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/9D.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "9D_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/9D.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "9E.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/9E.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "9E_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/9E_d.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "9F.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/9F.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "9F_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/9F.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "A0.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/A0.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "A0_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/A0.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "A1.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/A1.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "A1_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/A1.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "A2.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/A2.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "A2_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/A2.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "A3.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/A3.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "A3_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/A3.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "A4.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/A4.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "A4_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/A4.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "A5.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/A5.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "A5_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/A5.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "A6.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/A6.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "A6_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/A6.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "A7.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/A7.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "A7_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/A7.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "A8.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/A8.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "A8_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/A8.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "A9.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/A9.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "A9_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.00.0000/A9.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "kinoko_course.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/02.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "kinoko_course.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/02.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "volcano_course.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/03.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "volcano_course_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/03.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "shopping_course.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/05.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "shopping_course_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/05.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "truck_course.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/07.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "truck_course_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/07.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "AA.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/AA.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "AA_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/AA.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "AB.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/AB.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "AB_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/AB.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "AC.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/AC.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "AC_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/AC_d.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "AD.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/AD.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "AD_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/AD.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "AE.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/AE.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "AE_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/AE.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "AF.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/AF.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "AF_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/AF.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "B0.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/B0.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "B0_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/B0.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "B1.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/B1.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "B1_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/B1.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "B2.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/B2.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "B2_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/B2_d.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "B3.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/B3.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "B3_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/B3.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "B4.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/B4.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "B4_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/B4.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "B5.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/B5.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "B5_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/B5.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "B6.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/B6.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "B6_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/B6.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "B7.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/B7.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "B7_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/B7.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "B8.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/B8.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "B8_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/B8.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "B9.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/B9.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "B9_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/B9.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "BA.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/BA.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "BA_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/BA.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "BB.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/BB.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "BB_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/BB.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "BC.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/BC.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "BC_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/BC.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "BD.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/BD.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "BD_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/BD.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "BE.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/BE.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "BE_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/BE.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "BF.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/BF.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "BF_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/BF.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "C0.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/C0.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "C0_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/C0.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "C1.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/C1.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "C1_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.01.0000/C1.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "C2.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/C2.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "C2_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/C2.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "C3.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/C3.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "C3_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/C3.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "C4.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/C4.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "C4_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/C4.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "C5.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/C5.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "C5_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/C5.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "C6.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/C6.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "C6_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/C6.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "C7.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/C7.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "C7_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/C7.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "C8.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/C8.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "C8_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/C8.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "C9.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/C9.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "C9_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/C9.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "CA.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/CA.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "CA_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/CA.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "CB.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/CB.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "CB_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/CB.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "CC.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/CC.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "CC_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/CC.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "CD.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/CD.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "CD_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/CD.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "CE.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/CE.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "CE_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/CE.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "CF.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/CF.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "CF_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/CF.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "D0.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/D0.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "D0_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/D0.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "D1.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/D1.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "D1_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/D1.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "D2.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/D2.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "D2_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/D2.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "D3.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/D3.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "D3_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/D3.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "D4.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/D4.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "D4_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/D4.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "D5.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/D5.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "D5_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/D5.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "D6.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/D6.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "D6_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/D6.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "D7.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/D7.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "D7_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/D7.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "D8.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/D8.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "D8_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/D8.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "D9.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/D9.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "D9_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/D9.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "DA.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/DA.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "DA_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/DA.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "DB.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/DB.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "DB_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/DB.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "DC.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/DC.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "DC_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/DC.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "DD.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/DD.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "DD_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/DD.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "DE.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/DE.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "DE_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/DE.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "DF.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/DF.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "DF_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/DF.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "E0.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/E0.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "E0_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/E0.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "E1.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/E1.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "E1_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/E1.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "E2.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/E2.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "E2_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/E2.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "E3.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/E3.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "E3_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/E3.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "E4.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/E4.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "E4_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/E4.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "E5.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/E5.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "E5_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/E5.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "E6.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/E6.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "E6_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/E6.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "E7.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/E7.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "E7_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/E7_d.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "E8.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/E8.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "E8_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/E8.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "E9.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/E9.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "E9_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/E9.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "EA.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/EA.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "EA_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/EA.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "EB.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/EB.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "EB_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/EB.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "EC.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/EC.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "EC_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/EC.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "ED.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/ED.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "ED_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/ED.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "EE.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/EE.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "EE_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/EE.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "EF.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/EF.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "EF_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/EF.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "F0.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/F0.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "F0_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/F0.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "F1.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/F1.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "F1_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/F1.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "F2.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/F2.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "F2_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/F2.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "F3.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/F3.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "F3_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/F3.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "F4.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/F4.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "F4_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/F4.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "F5.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/F5.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "F5_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/F5.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "F6.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/F6.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "F6_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/F6.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "F7.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/F7.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "F7_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/F7.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "F8.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/F8.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "F8_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/F8.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "F9.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/F9.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "F9_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/F9.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "2A.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/2A.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "2A_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/2A.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "2B.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/2B.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "2B_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/2B.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "2C.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/2C.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "2C_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/2C.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "2D.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/2D.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "2D_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/2D.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "2E.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/2E.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "2E_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/2E.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "2F.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/2F.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "2F_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/2F.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "30.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/30.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "30_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/30.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "31.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/31.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "31_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/31.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "32.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/32.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "32_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/32.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "33.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/33.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "33_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/33.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "34.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/34.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "34_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/34.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "35.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/35.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "35_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/35.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "3B.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/3B.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "3B_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/3B.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "3C.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/3C.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "3C_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/3C.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "3D.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/3D.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "3D_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/3D.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "3E.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/3E.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "3E_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/3E.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "3F.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/3F.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "3F_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/Revo1.02.0000/3F.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Boot", "Strap", "eu"}, "English.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/menupatch/PAL/English.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Boot", "Strap", "eu"}, "Dutch.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/menupatch/PAL/Dutch.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Boot", "Strap", "eu"}, "French.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/menupatch/PAL/French.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Boot", "Strap", "eu"}, "German.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/menupatch/PAL/German.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Boot", "Strap", "eu"}, "Italian.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/menupatch/PAL/Italian.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Boot", "Strap", "eu"}, "Spanish_EU.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/menupatch/PAL/Spanish.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Boot", "Strap", "us"}, "English.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/menupatch/PAL/English.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Boot", "Strap", "us"}, "French.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/menupatch/PAL/English.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Boot", "Strap", "us"}, "Spanish_US.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/menupatch/PAL/English.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Boot", "Strap", "jp"}, "jp.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/menupatch/PAL/English.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "Award_E.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_E.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "Channel_E.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_E.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "Event_E.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_E.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "Globe_E.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_E.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "MenuMulti_E.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_E.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "MenuOther_E.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_E.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "MenuSingle_E.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_E.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "Present_E.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_E.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "Race_E.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_E.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "Title_E.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_E.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "Award_F.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_F.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "Channel_F.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_F.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "Event_F.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_F.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "Globe_F.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_F.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "MenuMulti_F.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_F.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "MenuOther_F.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_F.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "MenuSingle_F.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_F.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "Present_F.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_F.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "Race_F.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_F.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "Title_F.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_F.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "Award_G.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_G.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "Channel_G.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_G.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "Event_G.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_G.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "Globe_G.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_G.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "MenuMulti_G.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_G.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "MenuOther_G.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_G.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "MenuSingle_G.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_G.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "Present_G.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_G.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "Race_G.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_G.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "Title_G.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_G.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "Award_I.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_I.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "Channel_I.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_I.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "Event_I.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_I.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "Globe_I.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_I.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "MenuMulti_I.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_I.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "MenuOther_I.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_I.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "MenuSingle_I.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_I.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "Present_I.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_I.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "Race_I.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_I.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "Title_I.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_I.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "Award_S.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_S.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "Channel_S.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_S.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "Event_S.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_S.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "Globe_S.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_S.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "MenuMulti_S.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_S.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "MenuOther_S.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_S.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "MenuSingle_S.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_S.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "Present_S.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_S.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "Race_S.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_S.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "Title_S.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/textpatch/SuperMenu_S.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "Title.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/menupatch/Title.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "Globe.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/menupatch/Globe.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "Channel.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/menupatch/Channel.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "MenuSingle.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/menupatch/MenuSingle.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "MenuOther.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/menupatch/MenuOther.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "MenuMulti.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/menupatch/MenuMulti.szs", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"rel"}, "StaticR.rel", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA/mkwii/Level1/PAL/rel/StaticR.rel", false, false);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "41.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/old_garden_ds/chomp_valley+fix.szs", false, true);
  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "41_d.szs", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/old_garden_ds/chomp_valley+fix.szs", false, true);


  /* RiivolutionMod mod;
  mod.readFromXML("/home/heath/ctgpr.xml", "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA");

  for (Patch patch : mod.patches) {
    std::cout << "path" << patch.physicalPath << std::endl;
    File::AddToFileTree(rootEntry, patch.discPath , patch.physicalPath, patch.createFullPath, patch.createIfNotExists);
  } */

  /* File::AddToFileTree(rootEntry, "/Race/Course/ridgehighway_course.szs",
    "/media/heath/Windows/Users/User/Desktop/ridgehighway_course_halogen.szs", false, false);

  File::AddToFileTree(rootEntry, "/Race/Course/test.szs",
                      "/media/heath/Windows/Users/User/Desktop/test.txt", false, true); */

  /* File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "test.szs",
                               "/media/heath/Windows/Users/User/Desktop/test.txt", false, true);

  File::AddToFileTreeRecursive(rootEntry, {&parent_entry}, {""}, {}, "test.szs",
                               "/media/heath/Windows/Users/User/Desktop/test.txt", false, true); */


  /* pugi::xml_document doc;

  pugi::xml_parse_result result = doc.load_file("/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA/riivolution/mkwiiriivoslottest.xml"); */

  /* std::cout << "Load result: " << result.description()
            << ", mesh name: " << doc.child("mesh").attribute("name").value() << std::endl; */


  /*
  File::AddToFileTreeRecursive(
      rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "MenuOther.szs",
      "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/menupatch/MenuOther.szs", false, false);
  File::AddToFileTreeRecursive(
      rootEntry, {&parent_entry}, {""}, {"Scene", "UI"}, "MenuMulti.szs",
      "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/menupatch/MenuMulti.szs", false, false);
  File::AddToFileTreeRecursive(
      rootEntry, {&parent_entry}, {""}, {"rel"}, "StaticR.rel",
      "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA/mkwii/Level1/PAL/rel/StaticR.rel", false,
      false);
  File::AddToFileTreeRecursive(
      rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "41.szs",
      "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/old_garden_ds/chomp_valley+fix.szs",
      false, true);
  File::AddToFileTreeRecursive(
      rootEntry, {&parent_entry}, {""}, {"Race", "Course"}, "41_d.szs",
      "/media/heath/Windows/Users/User/Downloads/CTGP-R 1.02.0003 BETA//mkwii/old_garden_ds/chomp_valley+fix.szs",
      false, true);
*/



  /* File::AddToTreeRecursive(rootEntry, "", "/Race/Course", "test.szs",
                           "/media/heath/Windows/Users/User/Desktop/test.txt"); */

  ConvertUTF8NamesToSHIFTJIS(&rootEntry);

  u32 name_table_size = Common::AlignUp(ComputeNameSize(rootEntry), 1ull << m_address_shift);
  u64 total_entries = rootEntry.size + 1;  // The root entry itself isn't counted in rootEntry.size

  const u64 name_table_offset = total_entries * ENTRY_SIZE;
  m_fst_data.resize(name_table_offset + name_table_size);

  // 32 KiB aligned start of data on disc
  u64 current_data_address = Common::AlignUp(fst_address + m_fst_data.size(), 0x8000ull);

  u32 fst_offset = 0;   // Offset within FST data
  u32 name_offset = 0;  // Offset within name table
  u32 root_offset = 0;  // Offset of root of FST

  // write root entry
  WriteEntryData(&fst_offset, DIRECTORY_ENTRY, 0, 0, total_entries, m_address_shift);

  WriteDirectory(rootEntry, &fst_offset, &name_offset, &current_data_address, root_offset,
                 name_table_offset);

  // overflow check, compare the aligned name offset with the aligned name table size
  ASSERT(Common::AlignUp(name_offset, 1ull << m_address_shift) == name_table_size);

  // write FST size and location
  Write32((u32)(fst_address >> m_address_shift), 0x0424, &m_disc_header);
  Write32((u32)(m_fst_data.size() >> m_address_shift), 0x0428, &m_disc_header);
  Write32((u32)(m_fst_data.size() >> m_address_shift), 0x042c, &m_disc_header);

  m_contents.Add(fst_address, m_fst_data);

  m_data_size = current_data_address;
}

void DirectoryBlobPartition::WriteEntryData(u32* entry_offset, u8 type, u32 name_offset,
                                            u64 data_offset, u64 length, u32 address_shift)
{
  m_fst_data[(*entry_offset)++] = type;

  m_fst_data[(*entry_offset)++] = (name_offset >> 16) & 0xff;
  m_fst_data[(*entry_offset)++] = (name_offset >> 8) & 0xff;
  m_fst_data[(*entry_offset)++] = (name_offset)&0xff;

  Write32((u32)(data_offset >> address_shift), *entry_offset, &m_fst_data);
  *entry_offset += 4;

  Write32((u32)length, *entry_offset, &m_fst_data);
  *entry_offset += 4;
}

void DirectoryBlobPartition::WriteEntryName(u32* name_offset, const std::string& name,
                                            u64 name_table_offset)
{
  strncpy((char*)&m_fst_data[*name_offset + name_table_offset], name.c_str(), name.length() + 1);

  *name_offset += (u32)(name.length() + 1);
}

void DirectoryBlobPartition::WriteDirectory(const File::FSTEntry& parent_entry, u32* fst_offset,
                                            u32* name_offset, u64* data_offset,
                                            u32 parent_entry_index, u64 name_table_offset)
{
  std::vector<File::FSTEntry> sorted_entries = parent_entry.children;

  // Sort for determinism
  std::sort(sorted_entries.begin(), sorted_entries.end(),
            [](const File::FSTEntry& one, const File::FSTEntry& two) {
              const std::string one_upper = ASCIIToUppercase(one.virtualName);
              const std::string two_upper = ASCIIToUppercase(two.virtualName);
              return one_upper == two_upper ? one.virtualName < two.virtualName :
                                              one_upper < two_upper;
            });

  for (const File::FSTEntry& entry : sorted_entries)
  {
    if (entry.isDirectory)
    {
      u32 entry_index = *fst_offset / ENTRY_SIZE;
      WriteEntryData(fst_offset, DIRECTORY_ENTRY, *name_offset, parent_entry_index,
                     entry_index + entry.size + 1, 0);
      WriteEntryName(name_offset, entry.virtualName, name_table_offset);

      WriteDirectory(entry, fst_offset, name_offset, data_offset, entry_index, name_table_offset);
    }
    else
    {
      // put entry in FST
      WriteEntryData(fst_offset, FILE_ENTRY, *name_offset, *data_offset, entry.size,
                     m_address_shift);
      WriteEntryName(name_offset, entry.virtualName, name_table_offset);

      // write entry to virtual disc
      m_contents.Add(*data_offset, entry.size, entry.physicalName);

      // 32 KiB aligned - many games are fine with less alignment, but not all
      *data_offset = Common::AlignUp(*data_offset + entry.size, 0x8000ull);
    }
  }
}

static size_t ReadFileToVector(const std::string& path, std::vector<u8>* vector)
{
  File::IOFile file(path, "rb");
  size_t bytes_read;
  file.ReadArray<u8>(vector->data(), std::min<u64>(file.GetSize(), vector->size()), &bytes_read);
  return bytes_read;
}

static void PadToAddress(u64 start_address, u64* address, u64* length, u8** buffer)
{
  if (start_address > *address && *length > 0)
  {
    u64 padBytes = std::min(start_address - *address, *length);
    memset(*buffer, 0, (size_t)padBytes);
    *length -= padBytes;
    *buffer += padBytes;
    *address += padBytes;
  }
}

static void Write32(u32 data, u32 offset, std::vector<u8>* buffer)
{
  (*buffer)[offset++] = (data >> 24);
  (*buffer)[offset++] = (data >> 16) & 0xff;
  (*buffer)[offset++] = (data >> 8) & 0xff;
  (*buffer)[offset] = data & 0xff;
}

static u32 ComputeNameSize(const File::FSTEntry& parent_entry)
{
  u32 name_size = 0;
  for (const File::FSTEntry& entry : parent_entry.children)
  {
    if (entry.isDirectory)
      name_size += ComputeNameSize(entry);

    name_size += (u32)entry.virtualName.length() + 1;
  }
  return name_size;
}

static void ConvertUTF8NamesToSHIFTJIS(File::FSTEntry* parent_entry)
{
  for (File::FSTEntry& entry : parent_entry->children)
  {
    if (entry.isDirectory)
      ConvertUTF8NamesToSHIFTJIS(&entry);

    entry.virtualName = UTF8ToSHIFTJIS(entry.virtualName);
  }
}

static std::string ASCIIToUppercase(std::string str)
{
  std::transform(str.begin(), str.end(), str.begin(),
                 [](char c) { return std::toupper(c, std::locale::classic()); });
  return str;
}

}  // namespace DiscIO
