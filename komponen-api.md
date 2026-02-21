Berikut adalah komponen utama yang Anda butuhkan untuk membangun API tersebut:

1. Perancangan Struktur Data (Database Schema)
Anda memerlukan database (seperti SQLite atau MariaDB yang biasa Anda gunakan) untuk menyimpan setidaknya empat entitas utama:

Users: Membedakan antara peran 'Siswa' (yang dipantau) dan 'Guru/Admin' (yang memantau).

Habits: Daftar kebiasaan baik yang ingin dipantau (misal: Shalat Dhuha, Membaca Buku, Membuang Sampah).

Logs (Entries): Catatan harian aktivitas siswa.

Rewards/Points: Sistem poin untuk meningkatkan motivasi siswa.

2. Endpoints API Utama
API Anda setidaknya harus memiliki beberapa endpoint berikut:

A. Autentikasi & Profil
POST /auth/login: Untuk masuk ke sistem.

GET /user/profile: Mengambil data poin dan progres siswa.

B. Manajemen Kebiasaan (Habit Management)
GET /habits: Menampilkan daftar kebiasaan yang harus dilakukan hari ini.

POST /habits/log: Mengirimkan data bahwa siswa telah melakukan kebiasaan tertentu.

C. Monitoring & Laporan (Guru)
GET /admin/stats: Melihat statistik kebiasaan per kelas atau per siswa.

GET /admin/leaderboard: Menampilkan peringkat siswa berdasarkan konsistensi.

3. Tech Stack yang Disarankan
Melihat preferensi Anda pada pengembangan web modern dan efisien, berikut adalah kombinasi yang sangat cocok:

Runtime: Bun (sangat cepat untuk eksekusi skrip).

Framework: Hono (ringan, cepat, dan sangat mudah untuk membuat API).

ORM: Drizzle ORM (untuk interaksi database yang type-safe).

Database: SQLite (mudah dikelola untuk skala sekolah) atau PostgreSQL jika ingin lebih tangguh.

4. Fitur Keamanan & Validasi
JWT (JSON Web Token): Untuk memastikan hanya siswa yang bersangkutan yang bisa mengisi datanya sendiri.

Input Validation: Menggunakan library seperti Zod untuk memastikan data yang dikirim (misalnya tanggal atau ID kebiasaan) sudah benar sebelum masuk ke database.

Role-based Access Control (RBAC): Memastikan siswa tidak bisa mengakses endpoint statistik milik Guru.

5. Logika Bisnis (Gamifikasi)
Agar aplikasi ini menarik bagi siswa di sekolah, API Anda sebaiknya mendukung:

Streak Logic: Menghitung berapa hari berturut-turut siswa melakukan kebiasaan baik.

Daily Reset: Logika untuk memastikan daftar kebiasaan kosong kembali setiap hari baru.
