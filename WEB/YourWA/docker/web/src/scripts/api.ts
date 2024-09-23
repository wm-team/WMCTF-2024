export interface ProblemResponse {
    code: number;
    data: {
        title: string;
        description: string;
    };
}

export interface UploadSuccessResponse {
    code: number;
    data: {
        id: string;
        absent: boolean;
        content: string;
    };
}

export interface UploadErrorResponse {
    code: number;
    message: string;
}

export interface CancelResponse {
    code: number;
    message: string;
}

export interface RunCodeResponse {
    code: number;
    result: {
        error: boolean;
        etype?: "RTE" | "TLE" | "SE" | "CE" | "UKE";
        stdout: string;
        stderr: string;
    }
}

export interface SubmitCodeResponse {
    code: number;
    result: {
        error: boolean;
        etype?: "RTE" | "TLE" | "SE" | "CE" | "UKE";
        stdout: string;
        stderr: string;
        check: boolean;
    }
}