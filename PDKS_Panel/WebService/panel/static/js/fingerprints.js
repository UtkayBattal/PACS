document.addEventListener("DOMContentLoaded", function () {
  const viewFingerprintsBtn = document.getElementById("viewFingerprintsBtn");
  const enrollFingerprintBtn = document.getElementById(
    "enrollFingerprintBtn"
  );
  const userIdSelect = document.getElementById("user_id");
  const fingerIndexSelect = document.getElementById("finger_index");

  const fingerprintListEmpty = document.getElementById(
    "fingerprintListEmpty"
  );
  const fingerprintListLoading = document.getElementById(
    "fingerprintListLoading"
  );
  const fingerprintListError = document.getElementById(
    "fingerprintListError"
  );
  const fingerprintListErrorMsg = document.getElementById(
    "fingerprintListErrorMsg"
  );
  const fingerprintTable = document.getElementById("fingerprintTable");
  const fingerprintTableBody = document.getElementById(
    "fingerprintTableBody"
  );
  
  // Cihaz IP'sini sayfadan al
  const deviceIpElement = document.getElementById("deviceIpDisplay");
  let deviceIp = "";
  
  if (deviceIpElement) {
    const ipText = deviceIpElement.textContent;
    if (ipText && ipText.includes("Cihaz IP:")) {
      deviceIp = ipText.replace("Cihaz IP:", "").trim();
      console.log("Alınan cihaz IP:", deviceIp);
    }
  }

  if (!deviceIp) {
    console.error("Cihaz IP'si bulunamadı!");
    fingerprintListError.classList.remove("d-none");
    fingerprintListErrorMsg.innerHTML = '<i class="fas fa-exclamation-circle"></i> Cihaz IP adresi bulunamadı. Lütfen cihaz ayarlarını kontrol edin.';
    return;
  }

  // Parmak izi görüntüleme
  viewFingerprintsBtn.addEventListener("click", function () {
    const userId = userIdSelect.value;
    if (!userId) {
      alert("Lütfen bir personel seçin!");
      return;
    }

    console.log("Parmak izleri alınıyor - Kullanıcı ID:", userId);

    // Yükleniyor göster
    fingerprintListEmpty.classList.add("d-none");
    fingerprintListError.classList.add("d-none");
    fingerprintTable.classList.add("d-none");
    fingerprintListLoading.classList.remove("d-none");

    // API'den parmak izlerini al
    fetch(`/api/fingerprints/${userId}?device_ip=${encodeURIComponent(deviceIp)}`)
      .then(response => {
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
      })
      .then(data => {
        console.log("API yanıtı:", data);
        fingerprintListLoading.classList.add("d-none");

        if (data.success) {
          // Kullanıcı bilgilerini göster
          const userInfo = document.getElementById('fingerprint-user-info');
          userInfo.innerHTML = `
            <strong>Kullanıcı:</strong> ${data.data.name}<br>
            <strong>ID:</strong> ${data.data.user_id}<br>
            <strong>Cihaz UID:</strong> ${data.data.device_uid}
          `;

          // Parmak izi tablosunu temizle
          fingerprintTableBody.innerHTML = '';

          if (!data.data.fingerprints || data.data.fingerprints.length === 0) {
            fingerprintListEmpty.classList.remove("d-none");
            fingerprintListEmpty.innerHTML = '<div class="alert alert-warning"><i class="fas fa-exclamation-triangle"></i> Bu personele ait parmak izi kaydı bulunmuyor.</div>';
            console.log("Parmak izi kaydı bulunamadı");
          } else {
            console.log(`${data.data.fingerprints.length} adet parmak izi bulundu`);
            
            // Her kayıtlı parmak için satır ekle
            data.data.fingerprints.forEach(fp => {
              console.log("Parmak izi verisi:", fp);
              const row = document.createElement('tr');
              row.innerHTML = `
                <td>${fp.finger_index}</td>
                <td>${fp.finger_name}</td>
                <td><span class="badge bg-success">Kayıtlı</span></td>
                <td>${fp.size} byte</td>
                <td>
                  <button class="btn btn-sm btn-danger" onclick="deleteFingerprintHandler(${data.data.user_id}, ${fp.finger_index})">
                    <i class="fas fa-trash"></i> Sil
                  </button>
                </td>
              `;
              fingerprintTableBody.appendChild(row);
            });

            // Tabloyu göster
            fingerprintTable.classList.remove("d-none");
            document.getElementById('fingerprint-section').style.display = 'block';
          }
        } else {
          console.error("API hatası:", data.message);
          // Hata mesajını göster
          fingerprintListError.classList.remove("d-none");
          let errorMessage = data.message || 'Parmak izi verileri alınamadı.';
          if (data.debug_info) {
            console.log("Debug bilgisi:", data.debug_info);
            errorMessage += '<br><small class="text-muted">Debug bilgisi: ' + JSON.stringify(data.debug_info) + '</small>';
          }
          fingerprintListErrorMsg.innerHTML = `<i class="fas fa-exclamation-circle"></i> ${errorMessage}`;
        }
      })
      .catch(error => {
        console.error("Fetch hatası:", error);
        // Yükleniyor ve tablo gizle
        fingerprintListLoading.classList.add("d-none");
        fingerprintTable.classList.add("d-none");
        
        // Hata mesajını göster
        fingerprintListError.classList.remove("d-none");
        fingerprintListErrorMsg.innerHTML = `<i class="fas fa-exclamation-circle"></i> Sunucu ile iletişim kurulamadı: ${error.message}`;
      });
  });

  // Parmak izi kaydetme
  enrollFingerprintBtn.addEventListener("click", function () {
    const userId = userIdSelect.value;
    const fingerIndex = fingerIndexSelect.value;

    if (!userId) {
      alert("Lütfen bir personel seçin!");
      return;
    }

    if (
      !confirm(
        `${userId} numaralı kullanıcı için parmak izi kaydı başlatılacak. Devam etmek istiyor musunuz?`
      )
    ) {
      return;
    }

    // Form verilerini oluştur
    const formData = new FormData();
    formData.append("user_id", userId);
    formData.append("finger_index", fingerIndex);
    if (deviceIp) {
      formData.append("device_ip", deviceIp);
    }

    // API'ye istek gönder
    fetch("/api/fingerprints/enroll", {
      method: "POST",
      body: formData,
    })
      .then((response) => response.json())
      .then((data) => {
        if (data.success) {
          alert(data.message || "Parmak izi başarıyla kaydedildi.");
          // Başarılı ise, parmak izlerini yeniden yükle
          viewFingerprintsBtn.click();
        } else {
          alert("Hata: " + (data.message || "Parmak izi kaydedilemedi."));
        }
      })
      .catch((error) => {
        alert("Sunucu ile iletişim kurulamadı: " + error.message);
        console.error("Parmak izi kaydetme hatası:", error);
      });
  });

  // Parmak izi silme işlemi
  window.deleteFingerprintHandler = function(userId, fingerIndex) {
    if (!userId || fingerIndex === undefined) {
        alert("Geçersiz kullanıcı veya parmak izi bilgisi.");
        return;
    }
    
    if (!confirm(`Bu parmak izini silmek istediğinizden emin misiniz?`)) {
        return;
    }

    // Silme işlemi öncesi loading göster
    const row = document.querySelector(`tr[data-finger-index="${fingerIndex}"]`);
    if (row) {
        const deleteBtn = row.querySelector('.btn-danger');
        if (deleteBtn) {
            deleteBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Siliniyor...';
            deleteBtn.disabled = true;
        }
    }

    // Form verilerini oluştur
    const formData = new FormData();
    formData.append("user_id", userId);
    formData.append("finger_index", fingerIndex);
    
    // Device IP'sini al
    const deviceIpElement = document.getElementById("deviceIpDisplay");
    let deviceIp = "";
    if (deviceIpElement) {
        const ipText = deviceIpElement.textContent;
        if (ipText && ipText.includes("Cihaz IP:")) {
            deviceIp = ipText.replace("Cihaz IP:", "").trim();
        }
    }
    
    if (deviceIp) {
        formData.append("device_ip", deviceIp);
    }

    // API'ye istek gönder
    fetch("/api/fingerprints/delete", {
        method: "POST",
        body: formData,
        headers: {
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Başarılı silme işlemi
            alert(data.message || "Parmak izi başarıyla silindi.");
            // Parmak izlerini yeniden yükle
            document.getElementById("viewFingerprintsBtn").click();
        } else {
            throw new Error(data.message || "Parmak izi silinemedi.");
        }
    })
    .catch(error => {
        alert("Hata: " + error.message);
        console.error("Parmak izi silme hatası:", error);
        // Hata durumunda butonu eski haline getir
        if (row) {
            const deleteBtn = row.querySelector('.btn-danger');
            if (deleteBtn) {
                deleteBtn.innerHTML = '<i class="fas fa-trash"></i> Sil';
                deleteBtn.disabled = false;
            }
        }
    });
  };

  // Kullanıcı değiştiğinde parmak izi listesini temizle
  userIdSelect.addEventListener("change", function () {
    fingerprintTable.classList.add("d-none");
    fingerprintListError.classList.add("d-none");
    fingerprintListLoading.classList.add("d-none");
    fingerprintListEmpty.classList.remove("d-none");
    fingerprintListEmpty.innerHTML =
      '<p class="text-center text-muted">Parmak izi verisi görüntülemek için "Parmak İzlerini Görüntüle" butonuna tıklayın.</p>';
  });

  // Bağlantıyı kes butonu
  const disconnectBtn = document.getElementById("disconnectBtn");
  if (disconnectBtn) {
    disconnectBtn.addEventListener("click", function () {
      if (
        !confirm("Cihaz bağlantısını kesmek istediğinizden emin misiniz?")
      ) {
        return;
      }

      // Form verilerini oluştur
      const formData = new FormData();
      if (deviceIp) {
        formData.append("device_ip", deviceIp);
      }

      // API'ye istek gönder
      fetch("/api/device/disconnect", {
        method: "POST",
        body: formData,
      })
        .then((response) => response.json())
        .then((data) => {
          if (data.success) {
            alert(data.message || "Cihaz bağlantısı başarıyla kesildi.");
            // Sayfayı yeniden yükle
            window.location.reload();
          } else {
            alert("Hata: " + (data.message || "Cihaz bağlantısı kesilemedi."));
          }
        })
        .catch((error) => {
          alert("Sunucu ile iletişim kurulamadı: " + error.message);
          console.error("Cihaz bağlantısını kesme hatası:", error);
        });
    });
  }
});

function fillFingerprintTable(fingerprints) {
    const tableBody = document.getElementById('fingerprintTableBody');
    tableBody.innerHTML = '';
    
    if (!fingerprints || fingerprints.length === 0) {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td colspan="5" class="text-center">Kayıtlı parmak izi bulunamadı</td>
        `;
        tableBody.appendChild(row);
        return;
    }

    fingerprints.forEach((fingerprint, index) => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${fingerprint.finger_id}</td>
            <td>${getFingerName(fingerprint.finger_id)}</td>
            <td><span class="badge bg-success">Kayıtlı</span></td>
            <td>${fingerprint.size} byte</td>
            <td>
                <button class="btn btn-sm btn-danger delete-finger" data-finger-id="${fingerprint.finger_id}">
                    <i class="fas fa-trash"></i> Sil
                </button>
            </td>
        `;
        tableBody.appendChild(row);
    });
}

function getFingerName(fingerId) {
    const fingerNames = {
        1: "Sağ Başparmak",
        2: "Sağ İşaret Parmağı",
        3: "Sağ Orta Parmak",
        4: "Sağ Yüzük Parmağı",
        5: "Sağ Serçe Parmak",
        6: "Sol Başparmak",
        7: "Sol İşaret Parmağı",
        8: "Sol Orta Parmak",
        9: "Sol Yüzük Parmağı",
        10: "Sol Serçe Parmak"
    };
    return fingerNames[fingerId] || `Parmak ${fingerId}`;
} 