// MIT License
//
// Copyright(c) 2024 Matthieu Bucchianeri
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this softwareand associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and /or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "pch.h"

#include "log.h"
#include "utils.h"

#pragma intrinsic(_ReturnAddress)

using namespace logging;

namespace {
    using namespace utils;
    using namespace vr;

    // Dummy IVRCompositor implementations that LibMagic will hook into.
    struct CompositorStub_005 {
        struct Compositor_TextureBounds {
            float uMin, vMin;
            float uMax, vMax;
        };

        // clang-format off
        virtual void Vtable00() {};
        virtual void Vtable01() {};
        virtual void Vtable02() {};
        virtual void Vtable03() {};
        virtual void Vtable04() {};
        virtual void Vtable05() {};
        virtual void Vtable06() {};
        virtual void Submit( Hmd_Eye eEye, void* pTexture, Compositor_TextureBounds* pBounds ) {};
        // clang-format on
    };
    struct CompositorStub_028 {
        // clang-format off
        virtual void Vtable00() {};
        virtual void Vtable01() {};
        virtual void Vtable02() {};
        virtual void Vtable03() {};
        virtual void Vtable04() {};
        virtual EVRCompositorError Submit( EVREye eEye, const Texture_t *pTexture, const VRTextureBounds_t* pBounds = 0, EVRSubmitFlags nSubmitFlags = Submit_Default ) { return VRCompositorError_None; };
        // clang-format on
    };

    struct SwapchainMetadata {
        std::deque<uint32_t> acquired;
        uint32_t lastReleased;
        std::vector<ID3D11Texture2D*> image;
        UINT width, height;
    };

    std::mutex globalMutex;
    pvrEnvHandle pvr = nullptr;
    pvrSessionHandle pvrSession = nullptr;
    wil::unique_hmodule libMagic;
    std::unique_ptr<CompositorStub_005> compositorStubDummy;
    std::unique_ptr<CompositorStub_028> compositorStub;
    std::unordered_map<XrSwapchain, SwapchainMetadata> swapchains;

    HMODULE (*nextLoadLibraryA)(LPCSTR lpLibFileName) = nullptr;
    FARPROC (*nextGetProcAddress)(HMODULE hModule, LPCSTR lpProcName) = nullptr;
    int (*nextPVRgetIntConfig)(pvrHmdHandle hmdh, const char* key, int def_val) = nullptr;
    PFN_xrGetInstanceProcAddr nextXrGetInstanceProcAddr = nullptr;
    PFN_xrAcquireSwapchainImage nextXrAcquireSwapchainImage = nullptr;
    PFN_xrReleaseSwapchainImage nextXrReleaseSwapchainImage = nullptr;
    PFN_xrEndFrame nextXrEndFrame = nullptr;

    std::atomic<XrInstance> xrInstance = XR_NULL_HANDLE;
    PFN_xrEnumerateSwapchainImages nextXrEnumerateSwapchainImages = nullptr;

    void* VR_CALLTYPE Hooked_VR_GetGenericInterface(const char* pchInterfaceVersion, EVRInitError* peError) {
        const std::string_view interfaceVersion(pchInterfaceVersion);

        if (startsWith(interfaceVersion, std::string_view("IVRCompositor_"))) {
            std::unique_lock lock(globalMutex);

            if (compositorStub) {
                // Already fulfilled.
                return nullptr;
            }

            // Return our own IVRCompositor stub.
            if (interfaceVersion == IVRCompositor_Version) {
                if (!compositorStub) {
                    compositorStub = std::make_unique<CompositorStub_028>();
                }
                return compositorStub.get();
            }

            if (!compositorStubDummy) {
                compositorStubDummy = std::make_unique<CompositorStub_005>();
            }
            return compositorStubDummy.get();
        }
        return nullptr;
    }

    HMODULE Hooked_LoadLibraryA(LPCSTR lpLibFileName) {
        // Intercept LibMagic's calls to load openvr_api.dll.
        HMODULE callerModule;
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               (LPCSTR)_ReturnAddress(),
                               &callerModule)) {
            char moduleName[MAX_PATH]{};
            GetModuleFileNameA(callerModule, moduleName, sizeof(moduleName));
            if (endsWith(std::string_view(moduleName),
                         std::string_view(
#ifdef _WIN64
                             "LibMagicD3D1164.dll"
#else
                             "LibMagicD3D1132.dll"
#endif
                             ))) {
                const std::string_view libName(lpLibFileName);
                if (libName == "openvr_api.dll") {
                    // All we need is a valid handle.
                    return callerModule;
                }
            }
        }

        return nextLoadLibraryA(lpLibFileName);
    }

    FARPROC Hooked_GetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
        // Intercept LibMagic's calls to VR_GetGenericInterface().
        HMODULE callerModule;
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               (LPCSTR)_ReturnAddress(),
                               &callerModule)) {
            char moduleName[MAX_PATH]{};
            GetModuleFileNameA(callerModule, moduleName, sizeof(moduleName));
            if (endsWith(std::string_view(moduleName),
                         std::string_view(
#ifdef _WIN64
                             "LibMagicD3D1164.dll"
#else
                             "LibMagicD3D1132.dll"
#endif
                             ))) {
                const std::string_view procName(lpProcName);
                if (procName == "VR_GetGenericInterface") {
                    return reinterpret_cast<FARPROC>(Hooked_VR_GetGenericInterface);
                }
            }
        }

        return nextGetProcAddress(hModule, lpProcName);
    }

    int Hooked_PVRgetIntConfig(pvrHmdHandle hmdh, const char* key, int def_val) {
        std::string_view strkey(key);

        if (strkey == "foveated_rendering_level") {
            // Force LibMagic debug pattern.
            return 3;
        }

        return nextPVRgetIntConfig(hmdh, key, def_val);
    }

    void FakeOpenVRSubmission(const XrFrameEndInfo* frameEndInfo) {
        for (uint32_t i = 0; i < frameEndInfo->layerCount; i++) {
            if (frameEndInfo->layers[i]->type == XR_TYPE_COMPOSITION_LAYER_PROJECTION) {
                const XrCompositionLayerProjection* proj =
                    reinterpret_cast<const XrCompositionLayerProjection*>(frameEndInfo->layers[i]);
                if (proj->viewCount == 2 && proj->views[0].type == XR_TYPE_COMPOSITION_LAYER_PROJECTION_VIEW &&
                    proj->views[1].type == XR_TYPE_COMPOSITION_LAYER_PROJECTION_VIEW) {
                    for (uint32_t eye = 0; eye < 2; eye++) {
                        const auto cit = swapchains.find(proj->views[eye].subImage.swapchain);
                        if (cit != swapchains.cend() && !cit->second.image.empty()) {
                            const auto& swapchain = cit->second;

                            // Fake call to OpenVR. LibMagic will intercept it.
                            Texture_t texture{};
                            texture.eType = TextureType_DirectX;
                            texture.eColorSpace = ColorSpace_Auto;
                            texture.handle = swapchain.image[swapchain.lastReleased];
                            VRTextureBounds_t bounds{};
                            bounds.uMin = (float)proj->views[eye].subImage.imageRect.offset.x / swapchain.width;
                            bounds.uMax = (float)(proj->views[eye].subImage.imageRect.offset.x +
                                                  proj->views[eye].subImage.imageRect.extent.width) /
                                          swapchain.width;
                            bounds.vMin = (float)proj->views[eye].subImage.imageRect.offset.y / swapchain.height;
                            bounds.vMax = (float)(proj->views[eye].subImage.imageRect.offset.y +
                                                  proj->views[eye].subImage.imageRect.extent.height) /
                                          swapchain.height;
                            compositorStub->Submit(!eye ? Eye_Left : Eye_Right, &texture, &bounds, Submit_Default);
                        }
                    }
                }
                break;
            }
        }
    }

    XrResult XRAPI_CALL xrAcquireSwapchainImage(XrSwapchain swapchain,
                                                const XrSwapchainImageAcquireInfo* acquireInfo,
                                                uint32_t* index) {
        TraceLocalActivity(local);
        TraceLoggingWriteStart(local, "xrAcquireSwapchainImage");

        const XrResult result = nextXrAcquireSwapchainImage(swapchain, acquireInfo, index);
        if (XR_SUCCEEDED(result)) {
            std::unique_lock lock(globalMutex);

            // Keep track of the acquired images.
            auto it = swapchains.find(swapchain);
            if (it != swapchains.end()) {
                auto& metadata = it->second;
                metadata.acquired.push_back(*index);
            } else {
                SwapchainMetadata metadata{};
                metadata.acquired.push_back(*index);

                // Cache the swapchain images.
                uint32_t count = 0;
                if (!nextXrEnumerateSwapchainImages) {
                    nextXrGetInstanceProcAddr(xrInstance,
                                              "xrEnumerateSwapchainImages",
                                              reinterpret_cast<PFN_xrVoidFunction*>(&nextXrEnumerateSwapchainImages));
                }
                nextXrEnumerateSwapchainImages(swapchain, 0, &count, nullptr);
                std::vector<XrSwapchainImageD3D11KHR> images(count, {XR_TYPE_SWAPCHAIN_IMAGE_D3D11_KHR});
                if (XR_SUCCEEDED(nextXrEnumerateSwapchainImages(
                        swapchain, count, &count, reinterpret_cast<XrSwapchainImageBaseHeader*>(images.data())))) {
                    for (uint32_t i = 0; i < count; i++) {
                        metadata.image.push_back(images[i].texture);
                        if (i == 0) {
                            D3D11_TEXTURE2D_DESC desc{};
                            metadata.image[0]->GetDesc(&desc);
                            metadata.width = desc.Width;
                            metadata.height = desc.Height;
                        }
                    }
                }

                swapchains.insert_or_assign(swapchain, std::move(metadata));
            }
        }

        TraceLoggingWriteStop(local, "xrAcquireSwapchainImage");
        return result;
    }

    XrResult XRAPI_CALL xrReleaseSwapchainImage(XrSwapchain swapchain, const XrSwapchainImageReleaseInfo* releaseInfo) {
        TraceLocalActivity(local);
        TraceLoggingWriteStart(local, "xrReleaseSwapchainImage");

        const XrResult result = nextXrReleaseSwapchainImage(swapchain, releaseInfo);
        if (XR_SUCCEEDED(result)) {
            std::unique_lock lock(globalMutex);

            // Keep track of the last released image.
            auto it = swapchains.find(swapchain);
            if (it != swapchains.end()) {
                auto& metadata = it->second;
                metadata.lastReleased = metadata.acquired.front();
                metadata.acquired.pop_front();
            }
        }

        TraceLoggingWriteStop(local, "xrReleaseSwapchainImage");
        return result;
    }

    XrResult XRAPI_CALL xrEndFrame(XrSession session, const XrFrameEndInfo* frameEndInfo) {
        TraceLocalActivity(local);
        TraceLoggingWriteStart(local, "xrEndFrame");

        {
            std::unique_lock lock(globalMutex);

            if (compositorStub) {
                // If injection is underway, do the bridge from OpenXR to OpenVR hooks.
                if (frameEndInfo) {
                    lock.unlock();
                    FakeOpenVRSubmission(frameEndInfo);
                }
            } else if (!libMagic) {
                // Should we attempt to load LibMagic?
                if (!pvrSession && pvr) {
                    pvr_createSession(pvr, &pvrSession);

                    DetourFunctionAttach(pvr->pvr_interface->getIntConfig, Hooked_PVRgetIntConfig, nextPVRgetIntConfig);
                }
                if (pvrSession && pvr_getIntConfig(pvrSession, "enable_foveated_rendering", 0)) {
                    auto runtimePathString = RegGetString(HKEY_LOCAL_MACHINE,
                                                          L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{"
                                                          L"0D1DA8F2-89A7-4DAC-A9EF-B55E82CDA462}}_is1",
                                                          L"UninstallString");
                    trim(runtimePathString, L'\"');
                    const auto runtimePath = std::filesystem::path(runtimePathString).parent_path();
                    const auto libMagicPath = (runtimePath /
#ifdef _WIN64
                                               L"LibMagicD3D1164.dll"
#else
                                               L"LibMagicD3D1132.dll"
#endif
                                               )
                                                  .wstring();

                    // Drop the lock during loading to avoid recursive locking.
                    lock.unlock();
                    *libMagic.put() = LoadLibraryW(libMagicPath.c_str());
                }
            }
        }
        const XrResult result = nextXrEndFrame(session, frameEndInfo);

        TraceLoggingWriteStop(local, "xrEndFrame");
        return result;
    }

    XrResult XRAPI_CALL xrGetInstanceProcAddr(const XrInstance instance,
                                              const char* const name,
                                              PFN_xrVoidFunction* const function) {
        const XrResult result = nextXrGetInstanceProcAddr ? nextXrGetInstanceProcAddr(instance, name, function)
                                                          : XR_ERROR_FUNCTION_UNSUPPORTED;
        if (XR_SUCCEEDED(result)) {
            const std::string apiName(name);

            // Intercept the calls shimmed by our layer.
            if (apiName == "xrAcquireSwapchainImage") {
                nextXrAcquireSwapchainImage = reinterpret_cast<PFN_xrAcquireSwapchainImage>(*function);
                *function = reinterpret_cast<PFN_xrVoidFunction>(xrAcquireSwapchainImage);
            } else if (apiName == "xrReleaseSwapchainImage") {
                nextXrReleaseSwapchainImage = reinterpret_cast<PFN_xrReleaseSwapchainImage>(*function);
                *function = reinterpret_cast<PFN_xrVoidFunction>(xrReleaseSwapchainImage);
            } else if (apiName == "xrEndFrame") {
                nextXrEndFrame = reinterpret_cast<PFN_xrEndFrame>(*function);
                *function = reinterpret_cast<PFN_xrVoidFunction>(xrEndFrame);
            }

            if (instance != XR_NULL_HANDLE) {
                xrInstance.store(instance);
            }
        }

        return result;
    }

    XrResult XRAPI_CALL xrCreateApiLayerInstance(const XrInstanceCreateInfo* const instanceCreateInfo,
                                                 const struct XrApiLayerCreateInfo* const apiLayerInfo,
                                                 XrInstance* const instance) {
        if (!apiLayerInfo || apiLayerInfo->structType != XR_LOADER_INTERFACE_STRUCT_API_LAYER_CREATE_INFO ||
            apiLayerInfo->structVersion != XR_API_LAYER_CREATE_INFO_STRUCT_VERSION ||
            apiLayerInfo->structSize != sizeof(XrApiLayerCreateInfo) || !apiLayerInfo->nextInfo ||
            apiLayerInfo->nextInfo->structType != XR_LOADER_INTERFACE_STRUCT_API_LAYER_NEXT_INFO ||
            apiLayerInfo->nextInfo->structVersion != XR_API_LAYER_NEXT_INFO_STRUCT_VERSION ||
            apiLayerInfo->nextInfo->structSize != sizeof(XrApiLayerNextInfo) ||
            !apiLayerInfo->nextInfo->nextGetInstanceProcAddr || !apiLayerInfo->nextInfo->nextCreateApiLayerInstance) {
            return XR_ERROR_INITIALIZATION_FAILED;
        }

        nextXrGetInstanceProcAddr = apiLayerInfo->nextInfo->nextGetInstanceProcAddr;

        XrApiLayerCreateInfo chainApiLayerInfo = *apiLayerInfo;
        chainApiLayerInfo.nextInfo = apiLayerInfo->nextInfo->next;
        return apiLayerInfo->nextInfo->nextCreateApiLayerInstance(instanceCreateInfo, &chainApiLayerInfo, instance);
    }

} // namespace

XrResult XRAPI_CALL xrNegotiateLoaderApiLayerInterface(const XrNegotiateLoaderInfo* const loaderInfo,
                                                       const char* const apiLayerName,
                                                       XrNegotiateApiLayerRequest* const apiLayerRequest) {
    if (!loaderInfo || !apiLayerRequest || loaderInfo->structType != XR_LOADER_INTERFACE_STRUCT_LOADER_INFO ||
        loaderInfo->structVersion != XR_LOADER_INFO_STRUCT_VERSION ||
        loaderInfo->structSize != sizeof(XrNegotiateLoaderInfo) ||
        apiLayerRequest->structType != XR_LOADER_INTERFACE_STRUCT_API_LAYER_REQUEST ||
        apiLayerRequest->structVersion != XR_API_LAYER_INFO_STRUCT_VERSION ||
        apiLayerRequest->structSize != sizeof(XrNegotiateApiLayerRequest) ||
        loaderInfo->minInterfaceVersion > XR_CURRENT_LOADER_API_LAYER_VERSION ||
        loaderInfo->maxInterfaceVersion < XR_CURRENT_LOADER_API_LAYER_VERSION ||
        loaderInfo->maxInterfaceVersion > XR_CURRENT_LOADER_API_LAYER_VERSION ||
        loaderInfo->maxApiVersion < XR_CURRENT_API_VERSION || loaderInfo->minApiVersion > XR_CURRENT_API_VERSION) {
        return XR_ERROR_INITIALIZATION_FAILED;
    }

    // Setup our layer to intercept OpenXR calls.
    apiLayerRequest->layerInterfaceVersion = XR_CURRENT_LOADER_API_LAYER_VERSION;
    apiLayerRequest->layerApiVersion = XR_CURRENT_API_VERSION;
    apiLayerRequest->getInstanceProcAddr = reinterpret_cast<PFN_xrGetInstanceProcAddr>(xrGetInstanceProcAddr);
    apiLayerRequest->createApiLayerInstance = reinterpret_cast<PFN_xrCreateApiLayerInstance>(xrCreateApiLayerInstance);

    return XR_SUCCESS;
}

#pragma region "Logging"
//
// Log file helpers.
//

namespace logging {
    // {cbf3adcd-42b1-4c38-830b-91980af201f6}
    TRACELOGGING_DEFINE_PROVIDER(g_traceProvider,
                                 "PimaxMagic-OpenXR",
                                 (0xcbf3adcd, 0x42b1, 0x4c39, 0x93, 0x0b, 0x91, 0x98, 0x0a, 0xf2, 0x01, 0xf6));

    namespace {

        std::ofstream logStream;

        void InternalLog(const char* fmt, va_list va) {
            const std::time_t now = std::time(nullptr);

            char buf[1024];
            size_t offset = std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S %z: ", std::localtime(&now));
            vsnprintf_s(buf + offset, sizeof(buf) - offset, _TRUNCATE, fmt, va);
            OutputDebugStringA(buf);
            if (logStream.is_open()) {
                logStream << buf;
                logStream.flush();
            }
            TraceLoggingWrite(g_traceProvider, "Log", TLArg(buf, "Message"));
        }

    } // namespace

    void Log(const char* fmt, ...) {
        va_list va;
        va_start(va, fmt);
        InternalLog(fmt, va);
        va_end(va);
    }

    void StartLogging() {
        TraceLoggingRegister(g_traceProvider);
        const auto localAppData = std::filesystem::path(getenv("LOCALAPPDATA")) / "PimaxMagic-OpenXR";
        CreateDirectoryA(localAppData.string().c_str(), nullptr);

        char path[_MAX_PATH];
        GetModuleFileNameA(nullptr, path, sizeof(path));
        std::filesystem::path executable(path);
        executable = executable.filename();

        // Start logging to file.
        if (!logStream.is_open()) {
            std::string logFile = (localAppData / ("PimaxMagic-OpenXR-" + executable.string() + ".log")).string();
            logStream.open(logFile, std::ios_base::ate);
        }

        Log("Hello World from '%s'!\n", path);
    }

} // namespace logging
#pragma endregion

//
// DLL entry point.
//

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DetourRestoreAfterWith();
        StartLogging();
        pvr_initialise(&pvr);
        DetourDllAttach("kernel32.dll", "LoadLibraryA", Hooked_LoadLibraryA, nextLoadLibraryA);
        DetourDllAttach("kernel32.dll", "GetProcAddress", Hooked_GetProcAddress, nextGetProcAddress);
        break;

    case DLL_PROCESS_DETACH:
        DetourDllDetach("kernel32.dll", "LoadLibraryA", Hooked_LoadLibraryA, nextLoadLibraryA);
        DetourDllDetach("kernel32.dll", "GetProcAddress", Hooked_GetProcAddress, nextGetProcAddress);
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}
