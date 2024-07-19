// https://k94n.com/es6-modules-single-instance-pattern
export class EnvHandler {
  private static instance: EnvHandler;
  public envs: any;

  private constructor() {
    this.envs = {};
  }

  public static getInstance(): EnvHandler {
    if (!this.instance) {
      this.instance = new EnvHandler();
    }

    return this.instance;
  }

  public setEnvs(environmentVariables: any) {
    this.envs = environmentVariables;
  }
}
