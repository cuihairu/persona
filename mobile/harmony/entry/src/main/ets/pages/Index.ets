import { PersonaBridge } from '../persona/PersonaBridge';

/**
 * 原生骨架首屏：桥连通状态 + init/unlock/lock 生命周期骨架屏，
 * 语义对齐 Android / iOS。业务 UI（凭证库、TOTP、钱包）逐功能落地。
 */
@Entry
@Component
struct Index {
  @State status: string = '正在加载 persona 桥…';
  @State masterPassword: string = '';
  @State unlocked: boolean = false;

  aboutToAppear(): void {
    this.status = `桥状态 · persona ${PersonaBridge.version()}`;
    this.refreshUnlockState();
  }

  private submit(initial: boolean): void {
    if (this.masterPassword.length === 0) {
      this.status = '请输入主密码';
      return;
    }
    const dbPath = getContext().filesDir + '/persona.db';
    const result = initial
      ? PersonaBridge.serviceInit(dbPath, this.masterPassword)
      : PersonaBridge.serviceUnlock(this.masterPassword);
    if (result.success) {
      this.status = initial ? '初始化成功（已解锁）' : '解锁成功';
    } else {
      this.status = `失败：${result.error}`;
    }
    this.masterPassword = '';
    this.refreshUnlockState();
  }

  private lock(): void {
    const result = PersonaBridge.serviceLock();
    this.status = result.success ? '已锁定' : `锁定失败：${result.error}`;
    this.refreshUnlockState();
  }

  private refreshUnlockState(): void {
    this.unlocked = PersonaBridge.serviceIsUnlocked();
  }

  build() {
    Column({ space: 16 }) {
      Text(this.status)
        .fontSize(16)
        .width('100%')

      TextInput({ placeholder: '主密码' })
        .type(InputType.Password)
        .onChange((value: string) => {
          this.masterPassword = value;
        })

      Button('初始化 / 首次建户')
        .width('100%')
        .onClick(() => {
          this.submit(true);
        })

      Button('解锁')
        .width('100%')
        .onClick(() => {
          this.submit(false);
        })

      if (this.unlocked) {
        Button('锁定')
          .width('100%')
          .role(ButtonRole.Normal)
          .onClick(() => {
            this.lock();
          })
      }
    }
    .width('100%')
    .height('100%')
    .padding(24)
    .backgroundColor(Color.White)
  }
}
